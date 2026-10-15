# Local keys: the model providers for notebooks/prototype.ipynb, and the groups.io
# key that ingest/groupsio.py uses to download the CoSAI list archives.
#
#   cp set-keys.example.sh set-keys.sh     # set-keys.sh is gitignored
#   $EDITOR set-keys.sh
#   source set-keys.sh && jupyter lab
#
# Source it BEFORE starting Jupyter. A kernel inherits the environment of the process
# that launched it, so exporting in another terminal will not reach a running kernel --
# if the notebook says a key is unset after you have exported it, that is why.
#
# Not needed by the MCP server, which makes no model call and holds no key.

# Either paste a key directly:
#
#   export ANTHROPIC_API_KEY="sk-ant-..."
#
# or read one from a file, which keeps the secret out of your shell history and out of
# this file. Adjust the paths to wherever you keep them.

export ANTHROPIC_API_KEY="$(cat ~/.keys/anthropic 2>/dev/null)"
export OPENAI_API_KEY="$(cat ~/.keys/openai 2>/dev/null)"
export GEMINI_API_KEY="$(cat ~/.keys/gemini 2>/dev/null)"

# --- groups.io -------------------------------------------------------------------
#
# Your own personal API key, for downloading the CoSAI mailing list archives:
#
#     python -m bubo_graphrag.ingest.groupsio
#
# Create one at https://lists.oasis-open-projects.org/settings/apikeys. It is scoped
# to your own membership, needs no CSRF token or 2FA step, and can be revoked without
# changing your password. The archives are public, but the API authenticates every
# call, so each person runs this with their own key.

export GROUPSIO_API_KEY="$(cat ~/.keys/groupsio 2>/dev/null)"

# Optional: point at a different groups.io instance than the one in
# registry/mail-lists.yaml.
# export GROUPSIO_SITE="https://lists.oasis-open-projects.org"

# Optional: swap a model without editing the notebook.
# export COSAI_ANTHROPIC_MODEL="claude-fable-5"
# export COSAI_OPENAI_MODEL="gpt-5.6-luna"
# export COSAI_GEMINI_MODEL="gemini-3.1-pro-preview"

for _var in ANTHROPIC_API_KEY OPENAI_API_KEY GEMINI_API_KEY GROUPSIO_API_KEY; do
    if [ -z "${!_var}" ]; then
        echo "warning: $_var is empty -- check the path above" >&2
    fi
done
unset _var
