defmodule CredentialStoreTest do
  use ExUnit.Case, async: false

  @test_key "test-key-for-dev"
  @prod_key "test-key-for-prod"
  @encrypted_file "priv/secrets.enc.json"

  setup do
    File.mkdir_p!("priv")

    on_exit(fn ->
      File.rm(@encrypted_file)
      System.delete_env("CREDENTIAL_STORE_KEY")
    end)

    :ok
  end

  describe "encrypt_data/2 and decrypt_data/2" do
    test "round-trip for a simple string" do
      original = "my-secret-value"
      encrypted = CredentialStore.encrypt_data(original, @test_key)
      assert is_binary(encrypted)
      assert encrypted != original
      assert CredentialStore.decrypt_data(encrypted, @test_key) == original
    end

    test "round-trip for a map" do
      original = %{"API_KEY" => "sk-123", "DB_PASS" => "hunter2"}
      encrypted = CredentialStore.encrypt_data(original, @test_key)

      assert Map.keys(encrypted) == Map.keys(original)
      assert encrypted["API_KEY"] != "sk-123"

      decrypted = CredentialStore.decrypt_data(encrypted, @test_key)
      assert decrypted == original
    end

    test "round-trip for nested map" do
      original = %{"outer" => %{"inner" => "secret"}}
      encrypted = CredentialStore.encrypt_data(original, @test_key)
      decrypted = CredentialStore.decrypt_data(encrypted, @test_key)
      assert decrypted == original
    end

    test "round-trip for a list" do
      original = ["secret1", "secret2"]
      encrypted = CredentialStore.encrypt_data(original, @test_key)
      decrypted = CredentialStore.decrypt_data(encrypted, @test_key)
      assert decrypted == original
    end

    test "non-string values pass through unchanged" do
      assert CredentialStore.encrypt_data(42, @test_key) == 42
      assert CredentialStore.encrypt_data(true, @test_key) == true
      assert CredentialStore.encrypt_data(nil, @test_key) == nil
    end

    test "wrong key does not produce the original value" do
      encrypted = CredentialStore.encrypt_data("secret", @test_key)
      decrypted = CredentialStore.decrypt_data(encrypted, "wrong-key")
      assert decrypted != "secret"
    end
  end

  describe "load_section/1 and save_section/2" do
    test "save then load round-trips secrets" do
      System.put_env("CREDENTIAL_STORE_KEY", @test_key)
      secrets = %{"LLM_API_KEY" => "sk-ant-test123", "DB_PASS" => "password"}

      CredentialStore.save_section("dev", secrets)
      assert File.exists?(@encrypted_file)

      assert {:ok, loaded} = CredentialStore.load_section("dev")
      assert loaded == secrets
    end

    test "save_section injects sentinel and load_section strips it" do
      System.put_env("CREDENTIAL_STORE_KEY", @test_key)
      CredentialStore.save_section("dev", %{"KEY" => "val"})

      # The sentinel should be in the encrypted file
      enc_data = @encrypted_file |> File.read!() |> Jason.decode!()
      section = enc_data["dev"]
      assert Map.has_key?(section, "_cs_check")

      # But load_section should strip it
      assert {:ok, loaded} = CredentialStore.load_section("dev")
      refute Map.has_key?(loaded, "_cs_check")
      assert loaded == %{"KEY" => "val"}
    end

    test "load_section returns {:ok, empty map} when file does not exist" do
      System.put_env("CREDENTIAL_STORE_KEY", @test_key)
      File.rm(@encrypted_file)

      assert {:ok, %{}} = CredentialStore.load_section("dev")
    end

    test "load_section returns {:ok, empty map} for missing env section" do
      System.put_env("CREDENTIAL_STORE_KEY", @test_key)
      CredentialStore.save_section("dev", %{"KEY" => "val"})

      assert {:ok, %{}} = CredentialStore.load_section("staging")
    end

    test "load_section returns {:error, :wrong_key} with incorrect key" do
      System.put_env("CREDENTIAL_STORE_KEY", @test_key)
      CredentialStore.save_section("dev", %{"KEY" => "val"})

      System.put_env("CREDENTIAL_STORE_KEY", "totally-wrong-key")
      assert {:error, :wrong_key} = CredentialStore.load_section("dev")
    end

    test "saving one env does not destroy another" do
      System.put_env("CREDENTIAL_STORE_KEY", @test_key)
      CredentialStore.save_section("dev", %{"DEV_SECRET" => "dev-val"})

      System.put_env("CREDENTIAL_STORE_KEY", @prod_key)
      CredentialStore.save_section("prod", %{"PROD_SECRET" => "prod-val"})

      # Verify both sections exist in the file
      enc_data = @encrypted_file |> File.read!() |> Jason.decode!()
      assert Map.has_key?(enc_data, "dev")
      assert Map.has_key?(enc_data, "prod")

      # Load prod
      assert {:ok, loaded_prod} = CredentialStore.load_section("prod")
      assert loaded_prod == %{"PROD_SECRET" => "prod-val"}

      # Load dev with dev key
      System.put_env("CREDENTIAL_STORE_KEY", @test_key)
      assert {:ok, loaded_dev} = CredentialStore.load_section("dev")
      assert loaded_dev == %{"DEV_SECRET" => "dev-val"}
    end

    test "save_section raises without CREDENTIAL_STORE_KEY" do
      System.delete_env("CREDENTIAL_STORE_KEY")

      assert_raise RuntimeError, ~r/CREDENTIAL_STORE_KEY/, fn ->
        CredentialStore.save_section("dev", %{"KEY" => "val"})
      end
    end

    test "load_section raises without CREDENTIAL_STORE_KEY" do
      System.delete_env("CREDENTIAL_STORE_KEY")

      assert_raise RuntimeError, ~r/CREDENTIAL_STORE_KEY/, fn ->
        CredentialStore.load_section("dev")
      end
    end
  end

  describe "get/2 and get!/2" do
    test "get returns value for existing key" do
      secrets = %{"API_KEY" => "sk-123"}
      assert CredentialStore.get(secrets, "API_KEY") == "sk-123"
    end

    test "get returns nil for missing key" do
      secrets = %{"API_KEY" => "sk-123"}
      assert CredentialStore.get(secrets, "MISSING") == nil
    end

    test "get supports nested path" do
      secrets = %{"db" => %{"password" => "hunter2"}}
      assert CredentialStore.get(secrets, ["db", "password"]) == "hunter2"
    end

    test "get returns nil for missing nested path" do
      secrets = %{"db" => %{"password" => "hunter2"}}
      assert CredentialStore.get(secrets, ["db", "missing"]) == nil
    end

    test "get! returns value for existing key" do
      secrets = %{"API_KEY" => "sk-123"}
      assert CredentialStore.get!(secrets, "API_KEY") == "sk-123"
    end

    test "get! raises for missing key" do
      secrets = %{"API_KEY" => "sk-123"}

      assert_raise KeyError, fn ->
        CredentialStore.get!(secrets, "MISSING")
      end
    end
  end
end
