
## Validation finding (S12)

The connection layer now drives `TFlowControl`: every inbound DATA frame
accrues receive credit, and the connection emits a WINDOW_UPDATE (connection
level on stream 0, stream level on the lease's stream) once
`cWindowUpdateBatchSize` (32768) bytes have accrued. Without this wiring the
client advertised a 65535-byte window and never replenished it, so any
response body larger than 64 KiB stalled: nghttpd stopped sending once the
window hit zero and the read eventually raised `EHttpTimeout`
(`timed out reading response body`). Interop case A.7 (a 100 000-byte
response) covers the regression.
