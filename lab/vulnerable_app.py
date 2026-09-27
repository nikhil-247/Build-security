from fastapi import FastAPI, Response, Request
from fastapi.responses import JSONResponse, HTMLResponse

app = FastAPI(title="Intentionally Vulnerable World Monitor Lab")

REPORTS = {
    "1": {"id": "1", "owner": "alice", "classification": "internal", "summary": "Alice incident report"},
    "2": {"id": "2", "owner": "bob", "classification": "internal", "summary": "Bob incident report"},
}

@app.get("/", response_class=HTMLResponse)
def root(response: Response):
    response.set_cookie("wm_session", "demo-session")
    response.headers["X-Powered-By"] = "DemoFramework/1.0"
    response.headers["Access-Control-Allow-Origin"] = "*"
    return "<h1>World Monitor Lab</h1><p>Intentionally vulnerable local test app.</p>"

@app.get("/api/health")
def health():
    return {"status": "ok"}

@app.get("/api/reports/{report_id}")
def report(report_id: str, request: Request):
    report = REPORTS.get(report_id)
    if not report:
        return JSONResponse({"error": "not found"}, status_code=404)
    return report
