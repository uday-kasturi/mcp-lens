# mcp-lens

A semantic scanner for MCP (Model Context Protocol) tool definitions. It uses Claude to detect tool poisoning attacks -- hidden instructions embedded in tool descriptions, names, and schemas that redirect agent behavior in harmful ways.

## The problem

MCP tools can hide malicious instructions inside otherwise normal-looking definitions. A tool called "add" that adds two numbers can simultaneously instruct the agent to read SSH keys and pass them as a parameter. A "summarize" tool can redirect all outgoing emails to an attacker. These attacks are written in natural language, not code, so they bypass traditional pattern matching.

Regex-based scanners catch attacks with known signatures: explicit file paths, hardcoded URLs, banned keywords. They are blind to semantic attacks -- ones that describe harmful behavior without triggering any pattern. On a corpus of real-world attacks sourced from public security research repositories, regex detection falls to 0% on novel variants. This scanner gets 77.8%, with zero false positives on 50 legitimate tools.

## Results

Evaluated against 62 real tools sourced from public MCP attack research (invariantlabs-ai, Repello-AI, YassWorks, robbarto2, ivanoconnor, divyesh-0x01) and official MCP servers (modelcontextprotocol/servers and others). No synthetic data.

|                        | Regex baseline | Semantic (Sonnet) |
|------------------------|---------------|-------------------|
| Detection rate         | 25.0%         | 83.3%             |
| Novel variant detection| 0.0%          | 77.8%             |
| False positive rate    | 10.0%         | 0.0%              |
| F1                     | -             | 0.909             |

The 2 missed cases are sampling-based attacks where the malicious payload lives in the implementation code, not the tool definition. A static definition analyzer cannot catch those -- they are outside the scope of this approach.

Per-category (Sonnet):

| Category           | Detected | Total |
|--------------------|----------|-------|
| credential_harvest | 3        | 3     |
| shadowing          | 2        | 2     |
| rug_pull           | 1        | 1     |
| tool_poisoning     | 2        | 2     |
| indirect_injection | 2        | 4     |

## Usage

Requires the Claude Code CLI (`claude` in PATH) and Python 3.10+.

```
pip install -r requirements.txt
```

**Scan a single server definition:**

```
python cli.py server --server path/to/server.json
python cli.py server --server path/to/server.py
python cli.py server --server path/to/server.json --model sonnet
```

**Evaluate against the corpus:**

```
python cli.py eval --corpus ./corpus --compare-baseline
python cli.py eval --model sonnet --compare-baseline
```

**Run the regex baseline only (no API calls):**

```
python cli.py baseline
```

The scanner calls `claude -p` as a subprocess. No `ANTHROPIC_API_KEY` needed. Model defaults to Haiku for development iteration and Sonnet for final evaluation runs.

## How it works

Each tool definition (name, description, input schema) is passed to Claude with a structured prompt asking four questions:

1. Does the stated purpose match what the tool appears to actually do?
2. Do any instructions attempt to redirect agent behavior beyond the stated purpose?
3. Are there instructions to access, transmit, or expose sensitive files or credentials?
4. Does the tool attempt to influence how other tools in the session behave?

Responses are cached to disk (SHA-256 keyed on model + description + schema), so repeated runs and development iteration do not re-call the API.

## Corpus

`corpus/labels.json` contains 62 tools with full provenance. Every entry has a `source_repo` and `source_file` field pointing back to the original public repository. The `novel` field marks attacks that regex misses (9 of 12 malicious tools), which is the primary test set for semantic analysis.

Attack categories: tool_poisoning, shadowing, rug_pull, credential_harvest, indirect_injection.

## Limitations

- Sampling-based attacks (where the attack is in an LLM sampling prompt triggered at runtime, not in the tool definition) are not detectable by static definition analysis.
- The scanner evaluates definitions, not running behavior. A tool can pass this scanner and still be malicious at runtime.
- The corpus is small -- 12 real malicious tools from public repos. More labeled real-world data would strengthen any statistical claims.

## Running tests

```
python -m pytest tests/ -q
```

19 tests total. The 4 integration tests call the Claude CLI directly and require it to be authenticated.
