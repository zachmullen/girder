import mock
import pytest

from girder.models.item import Item


class Subclass(Item):
    pass


@pytest.mark.parametrize('cls', (Item, Subclass))
def testModelSingletonBehavior(cls):
    with mock.patch.object(cls, '__init__', return_value=None) as init:
        init.assert_not_called()
        cls()
        cls()
        init.assert_called_once()
