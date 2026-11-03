from .auth import current_user
from .store import Order, save


def create_order():
    order = Order(owner_id=current_user.id)
    save(order)
    return order
