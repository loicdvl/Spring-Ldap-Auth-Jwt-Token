package com.loicdev.springdemo.api.mapper;

import org.mapstruct.Mapper;
import org.mapstruct.factory.Mappers;

import com.loicdev.springdemo.api.model.CustomerDTO;
import com.loicdev.springdemo.domain.Customer;

@Mapper
public interface CustomerMapper {

	CustomerMapper INSTANCE = Mappers.getMapper(CustomerMapper.class);

    CustomerDTO customerToCustomerDTO(Customer customer);

    Customer customerDtoToCustomer(CustomerDTO customerDTO);
}
