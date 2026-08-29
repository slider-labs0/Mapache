package jakhar.aseem.diva;
import android.content.SharedPreferences;

public class InsecureDataStorage1Activity {
    void saveCredentials(String user, String pass) {
        // VULN: sensitive creds written world-readable in plaintext (CWE-312)
        SharedPreferences sp = getSharedPreferences("jakhar.aseem.diva",
                                                    MODE_WORLD_READABLE);
        SharedPreferences.Editor e = sp.edit();
        e.putString("user", user);
        e.putString("password", pass);      // stored as cleartext
        e.putString("creditcard", "4111111111111111");
        e.commit();
    }
}
