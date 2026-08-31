# dowse-plan

Resolves top-level Dowse hints into bounded account and storage targets without
depending on an EVM implementation or performing state reads.

The planner intentionally does not follow child selectors or resolve dependent
`SLoad` expressions. Callers can execute the returned plan on a background worker
pool without putting state I/O on the EVM execution thread.
