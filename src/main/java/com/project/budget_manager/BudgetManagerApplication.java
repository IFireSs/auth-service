package com.project.budget_manager;

import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
@ConfigurationPropertiesScan
public class BudgetManagerApplication {

    public static void main(String[] args) {
        SpringApplication.run(BudgetManagerApplication.class, args);
    }

}
