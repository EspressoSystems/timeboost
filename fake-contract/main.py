from dataclasses import dataclass
from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel
import typer
from typing import Optional, Dict
import uvicorn
from typing_extensions import Annotated

app = FastAPI()
cli = typer.Typer()


@dataclass
class CommitteeEntry:
    node_id: int
    public_key: str
    ip_addr: str

    def to_json(self) -> Dict[str, str]:
        return {
            "node_id": self.node_id,
            "public_key": self.public_key,
            "ip_addr": self.ip_addr,
        }


class ReadyPayload(BaseModel):
    node_id: int
    public_key: list[int]


COMMITTEE: list[CommitteeEntry] = []


@app.post("/ready/")
def ready(request: Request, payload: ReadyPayload):
    global COMMITTEE

    for entry in COMMITTEE:
        if payload.public_key == entry.public_key or payload.node_id == entry.node_id:
            raise HTTPException(
                status_code=401,
                detail=f"key '{payload.public_key}' was already registered",
            )

    e = CommitteeEntry(payload.node_id, payload.public_key, request.client[0])
    COMMITTEE.append(e)

    return e


@app.get("/start/")
def start():
    started = len(COMMITTEE) == app.state.committee_size
    committee = [e.to_json() for e in COMMITTEE] if started else []

    return {
        "started": started,
        "committee": committee,
    }


@cli.command()
def main(
    committee_size: Annotated[
        Optional[int],
        typer.Argument(help="How many nodes to wait for before starting"),
    ] = 5,
):
    # Store the committee_size in the app state
    app.state.committee_size = committee_size

    uvicorn.run(app, host="0.0.0.0", port=7200)


if __name__ == "__main__":
    cli()
