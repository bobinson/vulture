def send_error(resp, message, status=500):
    resp.status = status
    resp.write(message)
