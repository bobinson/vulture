package demo;

public class ReminderJob {
    private final Mailer mailer;
    private final InvoiceStore store;

    public void run() {
        remind(store.findOverdue());
    }

    private void remind(FindOverdueQuery overdue) {
        InvoiceRow row = overdue.first();
        mailer.sendReminderEmail(row.getCustomerEmail(), row.getNumber());
    }
}
