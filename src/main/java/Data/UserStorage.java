package Data;

import Model.User;

import java.util.HashMap;
import java.util.Map;

public class UserStorage {
    private Map<String, User> UserDatabase = new HashMap<String, User>();

    public void saveUser(User user) {
        UserDatabase.put(user.getUsername(), user);
    }
    public User getUser(String username){
        return UserDatabase.get(username);
    }
}
