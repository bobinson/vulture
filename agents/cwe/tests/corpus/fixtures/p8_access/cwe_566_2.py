def invoice_detail(request):
    invoice = Invoice.objects.get(pk=request.GET['id'])
    return render(request, 'invoice.html', {'invoice': invoice})
