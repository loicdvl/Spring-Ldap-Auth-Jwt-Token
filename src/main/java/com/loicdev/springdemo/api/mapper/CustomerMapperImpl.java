package com.loicdev.springdemo.api.mapper;

import org.springframework.stereotype.Component;

import com.loicdev.springdemo.api.model.CustomerDTO;
import com.loicdev.springdemo.controller.CustomerController;
import com.loicdev.springdemo.domain.Customer;

@Component
public class CustomerMapperImpl implements CustomerMapper {

	@Override
	public CustomerDTO customerToCustomerDTO(Customer customer) {
		if(customer == null)
			return null;
		
		CustomerDTO customerDTO = new CustomerDTO();
		customerDTO.setFirstname(customer.getFirstname());
		customerDTO.setLastname(customer.getLastname());
		customerDTO.setCustomerUrl(CustomerController.BASE_URL + "/" + customer.getId());
		
		return customerDTO;
	}

	@Override
	public Customer customerDtoToCustomer(CustomerDTO customerDTO) {
		if(customerDTO == null)
			return null;
		
		Customer customer = new Customer();
		customer.setFirstname(customerDTO.getFirstname());
		customer.setLastname(customerDTO.getLastname());
		
		return customer;
	}
}
