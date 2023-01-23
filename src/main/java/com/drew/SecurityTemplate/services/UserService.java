package com.drew.SecurityTemplate.services;

import com.drew.SecurityTemplate.models.User;
import com.drew.SecurityTemplate.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;


@Service
@Transactional
public class UserService {

    @Autowired
    private UserRepository userRepository;

    public void userAuthenticate(Long id){
       userRepository.findById(id).get().setEnabled(true);
    }

    public Boolean checkAuthStatus(Long id){
        return userRepository.findById(id).get().isEnabled();
    }

    public List<User> listAllUser() {
        return userRepository.findAll();
    }

    public void saveUser(User user) {
        userRepository.save(user);
    }

    public User getUser(Long id) {
        return userRepository.findById(id).get();
    }

    public void deleteUser(Long id) {
        userRepository.deleteById(id);
    }
}
