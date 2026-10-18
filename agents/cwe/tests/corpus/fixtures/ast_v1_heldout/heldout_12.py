# held-out heldout_12 (CWE-78): a shell=True Popen of a command string its caller builds from a POST field
# HELD-OUT-TOKENS: csrf_exempt
import subprocess

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt


def run_command(command):
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return process.communicate()


@csrf_exempt
def port_scan_api(request):
    if request.method == "POST":
        addr = request.POST.get("ip")
        command = "nmap " + addr
        out, err = run_command(command)
        return JsonResponse({"out": out.decode(), "err": err.decode()})
    return JsonResponse({"message": "method not allowed"}, status=405)
