from .models import Item


class ItemView:
    def delete_item(self, item_id):
        Item.objects.filter(id=item_id, owner=self.request.user).delete()
        return {"deleted": item_id}
