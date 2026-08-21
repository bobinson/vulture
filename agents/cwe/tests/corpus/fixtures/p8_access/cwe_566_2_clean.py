def invoice_detail(request):
    invoice = Invoice.objects.get(pk=request.GET['id'], owner_id=request.user.pk)
    return render(request, 'invoice.html', {'invoice': invoice})
