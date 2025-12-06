# CTF agent

Chatbot that uses [GeminiCLI](https://geminicli.com/docs/get-started/installation/) with MCP integration to assist in solving Capture-The-Flag (CTF) challenges.

More details on what CTFs are and the motivation for this project can be found in this [presentation](https://docs.google.com/presentation/d/1T-HfbbEgfL2h2r6NBUNwrbmsAUmm0qWLS7tQl8Q1pLE/edit?usp=sharing).

The final report (unfinished) is [here](https://www.overleaf.com/read/bswrsqgfvysb#187c0f).





# Architecture

The entire system is exposed via a client-facing MCP server. The only other entity the client interact with is this MCP server for tool calling. Therefore, this system should integrate with other LLMs as well.

User interface is the [GeminiCLI](https://geminicli.com/docs/get-started/installation/), so the LLM being tested is Gemini. 

The MCP server uses subprocess for short-lived tool calls/tasks and a docker container for long-lived tasks like fuzzing. It also provides an interface for the client to query the status of long-lived tasks.

![architecture](../ctf-agent/assets/architecture.png)


# Installation

Install [uv](https://github.com/astral-sh/uv).

Then, clone this repo, `cd` into it, then run:

```
uv init .
uv sync
```


# Running

