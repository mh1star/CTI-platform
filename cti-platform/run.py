"""مُشغّل المنصة: يجمع المسارات ويثبّت الجذر ثم يطلق uvicorn على البورت 8010."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def main() -> None:
    import uvicorn

    uvicorn.run("app.main:app", host="0.0.0.0", port=8010, reload=False)


if __name__ == "__main__":
    main()