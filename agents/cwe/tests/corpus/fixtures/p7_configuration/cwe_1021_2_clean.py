from django.shortcuts import render


@xframe_options_deny
def widget(request):
    return render(request, 'widget.html')
