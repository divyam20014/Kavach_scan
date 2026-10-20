"""Scanner modules. Scanners never import network/process modules: they use `JobContext`
and `app.integrations.http_service.HttpService`, so every request passes the scope gate."""
