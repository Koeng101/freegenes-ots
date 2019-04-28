import stamp
import io

data = io.BytesIO('hi'.encode('utf-8'))
print(stamp.TimeStamp(data))
