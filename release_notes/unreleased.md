**Unreleased**

* Escape email and resolve-name widget values before inserting them into JavaScript contexts.
* Bind interactive OAuth callbacks to the pending administrator-initiated flow.
* Restrict message-trace pagination to the expected Office365 reporting endpoint.
* Surface partial email parsing failures and tolerate malformed MIME and attachment metadata safely.
* Keep scheduled-poll checkpoints behind emails that failed processing so they are retried.
