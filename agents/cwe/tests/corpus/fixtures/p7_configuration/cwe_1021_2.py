from django.shortcuts import render


@xframe_options_exempt
def widget(request):
    return render(request, 'widget.html')
