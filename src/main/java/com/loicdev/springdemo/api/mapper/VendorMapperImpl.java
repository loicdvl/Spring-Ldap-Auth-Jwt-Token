package com.loicdev.springdemo.api.mapper;

import org.springframework.stereotype.Component;

import com.loicdev.springdemo.api.model.VendorDTO;
import com.loicdev.springdemo.controller.VendorController;
import com.loicdev.springdemo.domain.Vendor;

@Component
public class VendorMapperImpl implements VendorMapper {

	@Override
	public VendorDTO vendorToVendorDTO(Vendor vendor) {
		if(vendor == null)
			return null;
		
		VendorDTO vendorDTO = new VendorDTO();
		vendorDTO.setName(vendor.getName());
		vendorDTO.setVendorUrl(VendorController.BASE_URL + "/" + vendor.getId());
		
		return vendorDTO;
	}

	@Override
	public Vendor vendorDTOtoVendor(VendorDTO vendorDTO) {
		if(vendorDTO == null)
			return null;
		
		Vendor vendor = new Vendor();
		vendor.setName(vendorDTO.getName());
		
		return vendor;
	}
}
