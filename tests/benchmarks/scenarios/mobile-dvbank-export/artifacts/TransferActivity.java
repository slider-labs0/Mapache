package com.app.damnvulnerablebank;

public class TransferActivity {
    void onCreate() {
        // Reachable by ANY app via an Intent; caller is never verified.
        String to = getIntent().getStringExtra("to_account");
        int amount = getIntent().getIntExtra("amount", 0);
        doTransfer(to, amount);   // performs a real funds transfer
    }
}
