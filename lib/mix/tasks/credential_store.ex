defmodule Mix.Tasks.CredentialStore do
  @moduledoc """
  Interactive editor for encrypted credential store secrets.

  Decrypts secrets into memory, lets you add/edit/delete/view them,
  and re-encrypts on save. No decrypted file ever touches disk.

  ## Usage

      CREDENTIAL_STORE_KEY=my-key mix credential_store --env dev

  ## Options

    * `--env` - (required) the environment section to edit (e.g. dev, prod)
  """
  @shortdoc "Interactive credential store editor"

  use Mix.Task

  @impl Mix.Task
  def run(args) do
    {opts, _, _} = OptionParser.parse(args, strict: [env: :string])

    env =
      opts[:env] ||
        Mix.raise("--env is required. Usage: mix credential_store --env dev")

    CredentialStore.Editor.run(env)
  rescue
    e in RuntimeError ->
      if e.message =~ "CREDENTIAL_STORE_KEY" do
        Mix.raise(e.message)
      else
        reraise e, __STACKTRACE__
      end
  end
end
