# Memory

Mapache remembers within an engagement, across engagements, and semantically. This page
covers the memory subsystems and the cross-engagement learning that biases future runs.

## Session memory

`memory/session_memory.py` holds the turn-by-turn history of the current session. It works
with the conversation chain and context compaction so a long engagement stays coherent
without overflowing the context window.

## Notes

`memory/note_store.py` is a place for the agent to jot durable observations during an
engagement. The model can record a note and recall it later. `/memory` shows the current
memory state and `/user` records durable facts about the operator.

## Knowledge store and semantic recall

`memory/knowledge_store.py` and `memory/vector_store.py` store findings and support
semantic recall: the agent can retrieve a prior finding by meaning, not just by exact
match. This is what lets a finding persist across sessions and surface again when it
becomes relevant.

## The knowledge graph (findings store)

A disk-persisted knowledge graph records findings as structured nodes so a freshly spawned
specialist can query prior findings with a fresh context. This is the shared memory behind
the multi-agent supervisor: the lead and every operator read and write the same graph.
Model-facing tools are `kg_query` and `kg_add`.

## The operation plan

The operation plan (OPPLAN) is a living plan the model reads and updates over a long
engagement (`opplan_show`, `opplan_add`, `opplan_update`). It keeps the objective and the
outstanding steps coherent when the engagement spans many turns and several operators.

## Cross-engagement learning

Mapache keeps a cross-engagement learning store that records what worked on similar targets
before and biases routing toward those approaches on a new but similar target. A target
fingerprint is used to match, so a technique that won against a similar stack is surfaced
as a prior-win hint. This is how Mapache gets better with use rather than starting cold
every time.

## What is stored where

- Session history and the running summary live with the session.
- Notes and knowledge live in the note and knowledge stores.
- Findings live in the knowledge graph, which is shared across agents.
- The engagement audit trail lives in `engagements/` (see
  [Execution and OPSEC](execution-and-opsec.md)).
- Cross-engagement learning lives in its own store and persists between runs.
