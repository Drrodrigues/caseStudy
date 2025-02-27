package com.authentication.casestudio.control;

import com.authentication.casestudio.entities.Device;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface DeviceManager extends CrudRepository<Device, String> {



}
