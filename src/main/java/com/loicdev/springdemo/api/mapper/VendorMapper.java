package com.loicdev.springdemo.api.mapper;

import org.mapstruct.Mapper;
import org.mapstruct.factory.Mappers;

import com.loicdev.springdemo.api.model.VendorDTO;
import com.loicdev.springdemo.domain.Vendor;

@Mapper
public interface VendorMapper {

	VendorMapper INSTANCE = Mappers.getMapper(VendorMapper.class);

    VendorDTO vendorToVendorDTO(Vendor vendor);

    Vendor vendorDTOtoVendor(VendorDTO vendorDTO);
}
