defmodule CredentialStore.EditorTest do
  use ExUnit.Case, async: false

  @test_key "test-key-for-editor"
  @encrypted_file "priv/secrets.enc.json"

  setup do
    File.mkdir_p!("priv")
    System.put_env("CREDENTIAL_STORE_KEY", @test_key)

    on_exit(fn ->
      File.rm(@encrypted_file)
      System.delete_env("CREDENTIAL_STORE_KEY")
    end)

    :ok
  end

  describe "mask/1" do
    test "masks values >= 8 chars with prefix...suffix" do
      assert CredentialStore.Editor.mask("sk-ant-api03-longvalue123gAA") ==
               "sk-ant-api03...gAA"
    end

    test "masks short values with asterisks" do
      assert CredentialStore.Editor.mask("short") == "******"
    end

    test "masks exactly 8 char values with prefix...suffix" do
      assert CredentialStore.Editor.mask("12345678") == "12345678...678"
    end

    test "masks nil values" do
      assert CredentialStore.Editor.mask(nil) == "******"
    end
  end

  describe "run/2 with mock IO" do
    test "quit without saving does not write file" do
      File.rm(@encrypted_file)

      {gets, puts} = mock_io(["q\n"])
      CredentialStore.Editor.run("dev", gets: gets, puts: puts)

      refute File.exists?(@encrypted_file)
    end

    test "add a key then save writes encrypted file" do
      File.rm(@encrypted_file)

      {gets, puts} = mock_io(["a\n", "MY_KEY\n", "my-secret-value\n", "s\n"])
      CredentialStore.Editor.run("dev", gets: gets, puts: puts)

      assert File.exists?(@encrypted_file)
      assert {:ok, loaded} = CredentialStore.load_section("dev")
      assert loaded == %{"MY_KEY" => "my-secret-value"}
    end

    test "edit a key then save updates the value" do
      CredentialStore.save_section("dev", %{"API_KEY" => "old-value-here"})

      {gets, puts} = mock_io(["e\n", "1\n", "new-value-here\n", "s\n"])
      CredentialStore.Editor.run("dev", gets: gets, puts: puts)

      assert {:ok, loaded} = CredentialStore.load_section("dev")
      assert loaded["API_KEY"] == "new-value-here"
    end

    test "delete a key with confirmation then save" do
      CredentialStore.save_section("dev", %{"API_KEY" => "val", "OTHER" => "val2"})

      {gets, puts} = mock_io(["d\n", "1\n", "y\n", "s\n"])
      CredentialStore.Editor.run("dev", gets: gets, puts: puts)

      assert {:ok, loaded} = CredentialStore.load_section("dev")
      refute Map.has_key?(loaded, "API_KEY")
      assert Map.has_key?(loaded, "OTHER")
    end

    test "delete cancelled does not remove key" do
      CredentialStore.save_section("dev", %{"API_KEY" => "val"})

      {gets, puts} = mock_io(["d\n", "1\n", "n\n", "s\n"])
      CredentialStore.Editor.run("dev", gets: gets, puts: puts)

      assert {:ok, loaded} = CredentialStore.load_section("dev")
      assert Map.has_key?(loaded, "API_KEY")
    end

    test "view shows full value" do
      CredentialStore.save_section("dev", %{"API_KEY" => "full-secret-value"})

      {gets, puts} = mock_io(["v\n", "1\n", "q\n"])
      CredentialStore.Editor.run("dev", gets: gets, puts: puts)

      output = collect_puts()
      assert output =~ "API_KEY = full-secret-value"
    end

    test "starts with empty map and shows hint when no file exists" do
      File.rm(@encrypted_file)

      {gets, puts} = mock_io(["q\n"])
      CredentialStore.Editor.run("dev", gets: gets, puts: puts)

      output = collect_puts()
      assert output =~ "(no secrets yet"
      assert output =~ "[a]dd"
    end

    test "wrong key shows error and exits without writing" do
      CredentialStore.save_section("dev", %{"KEY" => "val"})

      System.put_env("CREDENTIAL_STORE_KEY", "totally-wrong-key")

      {gets, puts} = mock_io([])
      CredentialStore.Editor.run("dev", gets: gets, puts: puts)

      output = collect_puts()
      assert output =~ "does not match"
      assert output =~ "Check your key"
    end
  end

  defp mock_io(inputs) do
    {:ok, agent} = Agent.start_link(fn -> inputs end)

    gets = fn _prompt ->
      Agent.get_and_update(agent, fn
        [head | tail] -> {head, tail}
        [] -> {"\n", []}
      end)
    end

    puts = fn msg ->
      send(self(), {:io_puts, msg})
      :ok
    end

    {gets, puts}
  end

  defp collect_puts do
    collect_puts("")
  end

  defp collect_puts(acc) do
    receive do
      {:io_puts, msg} -> collect_puts(acc <> to_string(msg) <> "\n")
    after
      0 -> acc
    end
  end
end
