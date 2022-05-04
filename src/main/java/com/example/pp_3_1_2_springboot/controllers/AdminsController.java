package com.example.pp_3_1_2_springboot.controllers;

import com.example.pp_3_1_2_springboot.model.Role;
import com.example.pp_3_1_2_springboot.model.User;
import com.example.pp_3_1_2_springboot.service.RoleServiceImpl;
import com.example.pp_3_1_2_springboot.service.UserServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;
import java.util.HashSet;
import java.util.Set;

@Controller
@RequestMapping("/admin")
public class AdminsController {

    private UserServiceImpl userService;
    private RoleServiceImpl roleService;

    @Autowired
    public AdminsController(UserServiceImpl userService, RoleServiceImpl roleService) {
        this.userService = userService;
        this.roleService = roleService;
    }

    @GetMapping
    public String AllUsers(Principal principal, Model model) {
        User user = userService.getUserByLogin(principal.getName());
        model.addAttribute("user", user);
        model.addAttribute("users", userService.allUsers());
        return "admin";
    }

    @GetMapping("/new")
    public String newUser(Model model) {
        model.addAttribute("user", new User());
        model.addAttribute("roles", roleService.getAllRoles());
        return "new";
    }

    @PostMapping
    public String saveUser(@ModelAttribute("user") User user,
                           @RequestParam(required = false, value = "nameRoles") String[] roles) {
        Set<Role> roles1 = new HashSet<>();
        for (String role : roles) {
            roles1.add(roleService.getRoleByName(role));
        }
        user.setRoles(roles1);
        userService.save(user);
        return "redirect:/admin";
    }

    @GetMapping("/{id}/delete")
    public String delete(@PathVariable("id") int id) {
        userService.delete(id);
        return "redirect:/admin";
    }

    @GetMapping("/{id}/edit")
    public String edit(Model model, @PathVariable("id") int id) {
        model.addAttribute("user", userService.userById(id));
        model.addAttribute("roles", roleService.getAllRoles());
        return "/edit";
    }

    @PatchMapping("/{id}")
    public String update(@ModelAttribute("user") User user,
                         @RequestParam (value = "editRole") String[]roles1) {
        Set<Role> roles=new HashSet<>();
        for(String role:roles1){
            roles.add(roleService.getRoleByName(role));
        }
        user.setRoles(roles);
        userService.update(user);
        return "redirect:/admin";
    }
}
