from dataclasses import dataclass
from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel
import typer
from typing import Optional
import uvicorn
from typing_extensions import Annotated

app = FastAPI()
cli = typer.Typer()


@dataclass
class CommitteeEntry:
    public_key: str
    ip_addr: str


class ReadyPayload(BaseModel):
    public_key: str


COMMITTEE: list[CommitteeEntry] = []


@app.post("/ready/")
def ready(request: Request, payload: ReadyPayload):
    global COMMITTEE

    for entry in COMMITTEE:
        if payload.public_key == entry.public_key:
            raise HTTPException(
                status_code=401,
                detail=f"key '{payload.public_key}' was already registered",
            )

    COMMITTEE.append(CommitteeEntry(payload.public_key, request.client[0]))

    return {
        "client": request.client[0],
        "public_key": payload.public_key,
        "commitee_size": len(COMMITTEE),
    }


@app.get("/start/")
def start():
    return {"started": len(COMMITEE) == app.state.committee_size}


@cli.command()
def main(
    committee_size: Annotated[
        Optional[int],
        typer.Argument(help="How many nodes to wait for before starting"),
    ] = 5,
):
    # Store the committee_size in the app state
    app.state.committee_size = committee_size

    uvicorn.run(app, host="0.0.0.0", port=8000)


if __name__ == "__main__":
    cli()
