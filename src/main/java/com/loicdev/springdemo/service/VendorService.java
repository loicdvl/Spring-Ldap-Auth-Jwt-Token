package com.loicdev.springdemo.service;

import com.loicdev.springdemo.api.model.VendorDTO;
import com.loicdev.springdemo.api.model.VendorListDTO;

public interface VendorService {

    VendorDTO getVendorById(Long id);
    
    VendorDTO findVendorByName(String name);

    VendorListDTO getAllVendors();

    VendorDTO createNewVendor(VendorDTO vendorDTO);

    VendorDTO saveVendorByDTO(Long id, VendorDTO vendorDTO);

    VendorDTO patchVendor(Long id, VendorDTO vendorDTO);

    void deleteVendorById(Long id);
}