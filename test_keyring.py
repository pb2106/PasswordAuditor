import secretstorage
bus = secretstorage.dbus_init()
collection = secretstorage.get_default_collection(bus)
try:
    for item in collection.get_all_items():
        print("Label:", repr(item.get_label()))
except Exception as e:
    print("Error:", e)
