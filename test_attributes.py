import secretstorage
bus = secretstorage.dbus_init()
try:
    collections = secretstorage.get_all_collections(bus)
    for collection in collections:
        print("Collection:", collection.get_label())
        for item in collection.get_all_items():
            print("  Label:", item.get_label())
            print("  Attributes:", item.get_attributes())
except Exception as e:
    print("Error:", e)
