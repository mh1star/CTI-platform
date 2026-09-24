"""إعدادات مشتركة لاختبارات منصة CTI."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.ner.extractor import Extractor


@pytest.fixture(scope="session")
def engine() -> Extractor:
    from app.runtime import get_model

    return Extractor(get_model())