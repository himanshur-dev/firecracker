/// Contains the state and associated methods required for the Firecracker VMM.




// This module is for logic related to building the VMM object 
mod VmmBuild {
    // This is the module for logic specific to the aarch64 platform
    pub mod Aarch64 {
        /// Sets RDA bit in serial console
        pub fn emulate_serial_init(&self) -> Result<(), EmulateSerialInitError> {
            // When restoring from a previously saved state, there is no serial
            // driver initialization, therefore the RDA (Received Data Available)
            // interrupt is not enabled. Because of that, the driver won't get
            // notified of any bytes that we send to the guest. The clean solution
            // would be to save the whole serial device state when we do the vm
            // serialization. For now we set that bit manually

                let serial_bus_device = self.get_bus_device(DeviceType::Serial, "Serial");
                if serial_bus_device.is_none() {
                    return Ok(());
                }
                let mut serial_device_locked =
                    serial_bus_device.unwrap().lock().expect("Poisoned lock");
                let serial = serial_device_locked
                    .serial_mut()
                    .expect("Unexpected BusDeviceType");

                serial
                    .serial
                    .write(IER_RDA_OFFSET, IER_RDA_BIT)
                    .map_err(|_| EmulateSerialInitError(std::io::Error::last_os_error()))?;
                Ok(())
        }

        pub fn save_state(&mut self, vm_info: &VmInfo) -> Result<MicrovmState, MicrovmStateError> {
            use self::MicrovmStateError::SaveVmState;
            let vcpu_states = self.save_vcpu_states()?;
            let vm_state = {
                let mpidrs = construct_kvm_mpidrs(&vcpu_states);
                self.vm.save_state(&mpidrs).map_err(SaveVmState)?
            };
            let device_states = self.mmio_device_manager.save();
        
            let memory_state = self.guest_memory().describe();
        
            Ok(MicrovmState {
                vm_info: vm_info.clone(),
                memory_state,
                vm_state,
                vcpu_states,
                device_states,
            })
        }
        
    }
    

    pub mod X86_64 {
        /// Injects CTRL+ALT+DEL keystroke combo in the i8042 device.
        pub fn emulate_serial_init(&self) -> Result<(), EmulateSerialInitError> {
            let mut guard = self
                .pio_device_manager
                .stdio_serial
                .lock()
                .expect("Poisoned lock");
            let serial = guard.serial_mut().unwrap();

            serial
                .serial
                .write(IER_RDA_OFFSET, IER_RDA_BIT)
                .map_err(|_| EmulateSerialInitError(std::io::Error::last_os_error()))?;
            Ok(())
        }
        
        pub fn send_ctrl_alt_del(&mut self) -> Result<(), VmmError> {
            self.pio_device_manager
                .i8042
                .lock()
                .expect("i8042 lock was poisoned")
                .i8042_device_mut()
                .unwrap()
                .trigger_ctrl_alt_del()
                .map_err(VmmError::I8042Error)
        }

        pub fn save_state(&mut self, vm_info: &VmInfo) -> Result<MicrovmState, MicrovmStateError> {
            use self::MicrovmStateError::SaveVmState;
            let vcpu_states = self.save_vcpu_states()?;
            let vm_state = self.vm.save_state().map_err(SaveVmState)?;
            let device_states = self.mmio_device_manager.save();
        
            let memory_state = self.guest_memory().describe();
            let acpi_dev_state = self.acpi_device_manager.save();
        
            Ok(MicrovmState {
                vm_info: vm_info.clone(),
                memory_state,
                vm_state,
                vcpu_states,
                device_states,
                acpi_dev_state,
            })
        }

        


    }

}



#[derive(Debug)]
pub struct X86_64_Devices {
    pio_device_manager: PortIODeviceManager,
    acpi_device_manager: ACPIDeviceManager
}


#[derive(Debug)]
pub struct Vmm {
    events_observer: Option<std::io::Stdin>,
    instance_info: InstanceInfo,
    shutdown_exit_code: Option<FcExitCode>,

    // Guest VM core resources.
    vm: Vm,
    guest_memory: GuestMemoryMmap,
    // Save UFFD in order to keep it open in the Firecracker process, as well.
    // Since this field is never read again, we need to allow `dead_code`.
    #[allow(dead_code)]
    uffd: Option<Uffd>,
    vcpus_handles: Vec<VcpuHandle>,
    // Used by Vcpus and devices to initiate teardown; Vmm should never write here.
    vcpus_exit_evt: EventFd,

    // Allocator for guest resrouces
    resource_allocator: ResourceAllocator,
    // Guest VM devices.
    mmio_device_manager: MMIODeviceManager,
    // Devices specifically for the x86_64 platform
    devices_for_x86_64: Option<X86_64_Devices>,
}

impl Vmm {
    #[cfg(target_arch = "aarch64")]
    use VmmBuild::aarch64::*;
    #[cfg(target_arch = "x86_64")]
    use VmmBuild::x86_64::*;

    /// Gets Vmm version.
    pub fn version(&self) -> String {
        self.instance_info.vmm_version.clone()
    }

    /// Gets Vmm instance info.
    pub fn instance_info(&self) -> InstanceInfo {
        self.instance_info.clone()
    }

    /// Provides the Vmm shutdown exit code if there is one.
    pub fn shutdown_exit_code(&self) -> Option<FcExitCode> {
        self.shutdown_exit_code
    }

    /// Gets the specified bus device.
    pub fn get_bus_device(
        &self,
        device_type: DeviceType,
        device_id: &str,
    ) -> Option<&Mutex<devices::bus::BusDevice>> {
        self.mmio_device_manager.get_device(device_type, device_id)
    }

    /// Starts the microVM vcpus.
    ///
    /// # Errors
    ///
    /// When:
    /// - [`vmm::VmmEventsObserver::on_vmm_boot`] errors.
    /// - [`vmm::vstate::vcpu::Vcpu::start_threaded`] errors.
    pub fn start_vcpus(
        &mut self,
        mut vcpus: Vec<Vcpu>,
        vcpu_seccomp_filter: Arc<BpfProgram>,
    ) -> Result<(), StartVcpusError> {
        let vcpu_count = vcpus.len();
        let barrier = Arc::new(Barrier::new(vcpu_count + 1));

        if let Some(stdin) = self.events_observer.as_mut() {
            // Set raw mode for stdin.
            stdin.lock().set_raw_mode().map_err(|err| {
                warn!("Cannot set raw mode for the terminal. {:?}", err);
                err
            })?;

            // Set non blocking stdin.
            stdin.lock().set_non_block(true).map_err(|err| {
                warn!("Cannot set non block for the terminal. {:?}", err);
                err
            })?;
        }

        Vcpu::register_kick_signal_handler();

        self.vcpus_handles.reserve(vcpu_count);

        for mut vcpu in vcpus.drain(..) {
            vcpu.set_mmio_bus(self.mmio_device_manager.bus.clone());
            #[cfg(target_arch = "x86_64")]
            vcpu.kvm_vcpu
                .set_pio_bus(self.pio_device_manager.io_bus.clone());

            self.vcpus_handles
                .push(vcpu.start_threaded(vcpu_seccomp_filter.clone(), barrier.clone())?);
        }
        self.instance_info.state = VmState::Paused;
        // Wait for vCPUs to initialize their TLS before moving forward.
        barrier.wait();

        Ok(())
    }

    /// Sends a resume command to the vCPUs.
    pub fn resume_vm(&mut self) -> Result<(), VmmError> {
        self.mmio_device_manager.kick_devices();

        // Send the events.
        self.vcpus_handles
            .iter()
            .try_for_each(|handle| handle.send_event(VcpuEvent::Resume))
            .map_err(|_| VmmError::VcpuMessage)?;

        // Check the responses.
        if self
            .vcpus_handles
            .iter()
            .map(|handle| handle.response_receiver().recv_timeout(RECV_TIMEOUT_SEC))
            .any(|response| !matches!(response, Ok(VcpuResponse::Resumed)))
        {
            return Err(VmmError::VcpuMessage);
        }

        self.instance_info.state = VmState::Running;
        Ok(())
    }

    /// Sends a pause command to the vCPUs.
    pub fn pause_vm(&mut self) -> Result<(), VmmError> {
        // Send the events.
        self.vcpus_handles
            .iter()
            .try_for_each(|handle| handle.send_event(VcpuEvent::Pause))
            .map_err(|_| VmmError::VcpuMessage)?;

        // Check the responses.
        if self
            .vcpus_handles
            .iter()
            .map(|handle| handle.response_receiver().recv_timeout(RECV_TIMEOUT_SEC))
            .any(|response| !matches!(response, Ok(VcpuResponse::Paused)))
        {
            return Err(VmmError::VcpuMessage);
        }

        self.instance_info.state = VmState::Paused;
        Ok(())
    }

    /// Returns a reference to the inner `GuestMemoryMmap` object.
    pub fn guest_memory(&self) -> &GuestMemoryMmap {
        &self.guest_memory
    }
    
    fn save_vcpu_states(&mut self) -> Result<Vec<VcpuState>, MicrovmStateError> {
        for handle in self.vcpus_handles.iter() {
            handle
                .send_event(VcpuEvent::SaveState)
                .map_err(MicrovmStateError::SignalVcpu)?;
        }

        let vcpu_responses = self
            .vcpus_handles
            .iter()
            // `Iterator::collect` can transform a `Vec<Result>` into a `Result<Vec>`.
            .map(|handle| handle.response_receiver().recv_timeout(RECV_TIMEOUT_SEC))
            .collect::<Result<Vec<VcpuResponse>, RecvTimeoutError>>()
            .map_err(|_| MicrovmStateError::UnexpectedVcpuResponse)?;

        let vcpu_states = vcpu_responses
            .into_iter()
            .map(|response| match response {
                VcpuResponse::SavedState(state) => Ok(*state),
                VcpuResponse::Error(err) => Err(MicrovmStateError::SaveVcpuState(err)),
                VcpuResponse::NotAllowed(reason) => Err(MicrovmStateError::NotAllowed(reason)),
                _ => Err(MicrovmStateError::UnexpectedVcpuResponse),
            })
            .collect::<Result<Vec<VcpuState>, MicrovmStateError>>()?;

        Ok(vcpu_states)
    }

    /// Dumps CPU configuration.
    pub fn dump_cpu_config(&mut self) -> Result<Vec<CpuConfiguration>, DumpCpuConfigError> {
        for handle in self.vcpus_handles.iter() {
            handle
                .send_event(VcpuEvent::DumpCpuConfig)
                .map_err(DumpCpuConfigError::SendEvent)?;
        }

        let vcpu_responses = self
            .vcpus_handles
            .iter()
            .map(|handle| handle.response_receiver().recv_timeout(RECV_TIMEOUT_SEC))
            .collect::<Result<Vec<VcpuResponse>, RecvTimeoutError>>()
            .map_err(|_| DumpCpuConfigError::UnexpectedResponse)?;

        let cpu_configs = vcpu_responses
            .into_iter()
            .map(|response| match response {
                VcpuResponse::DumpedCpuConfig(cpu_config) => Ok(*cpu_config),
                VcpuResponse::Error(err) => Err(DumpCpuConfigError::DumpCpuConfig(err)),
                VcpuResponse::NotAllowed(reason) => Err(DumpCpuConfigError::NotAllowed(reason)),
                _ => Err(DumpCpuConfigError::UnexpectedResponse),
            })
            .collect::<Result<Vec<CpuConfiguration>, DumpCpuConfigError>>()?;

        Ok(cpu_configs)
    }

    /// Retrieves the KVM dirty bitmap for each of the guest's memory regions.
    pub fn reset_dirty_bitmap(&self) {
        self.guest_memory
            .iter()
            .enumerate()
            .for_each(|(slot, region)| {
                let _ = self
                    .vm
                    .fd()
                    .get_dirty_log(u32::try_from(slot).unwrap(), u64_to_usize(region.len()));
            });
    }

    /// Retrieves the KVM dirty bitmap for each of the guest's memory regions.
    pub fn get_dirty_bitmap(&self) -> Result<DirtyBitmap, VmmError> {
        let mut bitmap: DirtyBitmap = HashMap::new();
        self.guest_memory
            .iter()
            .enumerate()
            .try_for_each(|(slot, region)| {
                let bitmap_region = self
                    .vm
                    .fd()
                    .get_dirty_log(u32::try_from(slot).unwrap(), u64_to_usize(region.len()))?;
                bitmap.insert(slot, bitmap_region);
                Ok(())
            })
            .map_err(VmmError::DirtyBitmap)?;
        Ok(bitmap)
    }

    /// Enables or disables KVM dirty page tracking.
    pub fn set_dirty_page_tracking(&mut self, enable: bool) -> Result<(), VmmError> {
        // This function _always_ results in an ioctl update. The VMM is stateless in the sense
        // that it's unaware of the current dirty page tracking setting.
        // The VMM's consumer will need to cache the dirty tracking setting internally. For
        // example, if this function were to be exposed through the VMM controller, the VMM
        // resources should cache the flag.
        self.vm
            .set_kvm_memory_regions(&self.guest_memory, enable)
            .map_err(VmmError::Vm)
    }

    /// Updates the path of the host file backing the emulated block device with id `drive_id`.
    /// We update the disk image on the device and its virtio configuration.
    pub fn update_block_device_path(
        &mut self,
        drive_id: &str,
        path_on_host: String,
    ) -> Result<(), VmmError> {
        self.mmio_device_manager
            .with_virtio_device_with_id(TYPE_BLOCK, drive_id, |block: &mut Block| {
                block
                    .update_disk_image(path_on_host)
                    .map_err(|err| err.to_string())
            })
            .map_err(VmmError::DeviceManager)
    }

    /// Updates the rate limiter parameters for block device with `drive_id` id.
    pub fn update_block_rate_limiter(
        &mut self,
        drive_id: &str,
        rl_bytes: BucketUpdate,
        rl_ops: BucketUpdate,
    ) -> Result<(), VmmError> {
        self.mmio_device_manager
            .with_virtio_device_with_id(TYPE_BLOCK, drive_id, |block: &mut Block| {
                block
                    .update_rate_limiter(rl_bytes, rl_ops)
                    .map_err(|err| err.to_string())
            })
            .map_err(VmmError::DeviceManager)
    }

    /// Updates the rate limiter parameters for block device with `drive_id` id.
    pub fn update_vhost_user_block_config(&mut self, drive_id: &str) -> Result<(), VmmError> {
        self.mmio_device_manager
            .with_virtio_device_with_id(TYPE_BLOCK, drive_id, |block: &mut Block| {
                block.update_config().map_err(|err| err.to_string())
            })
            .map_err(VmmError::DeviceManager)
    }

    /// Updates the rate limiter parameters for net device with `net_id` id.
    pub fn update_net_rate_limiters(
        &mut self,
        net_id: &str,
        rx_bytes: BucketUpdate,
        rx_ops: BucketUpdate,
        tx_bytes: BucketUpdate,
        tx_ops: BucketUpdate,
    ) -> Result<(), VmmError> {
        self.mmio_device_manager
            .with_virtio_device_with_id(TYPE_NET, net_id, |net: &mut Net| {
                net.patch_rate_limiters(rx_bytes, rx_ops, tx_bytes, tx_ops);
                Ok(())
            })
            .map_err(VmmError::DeviceManager)
    }

    /// Returns a reference to the balloon device if present.
    pub fn balloon_config(&self) -> Result<BalloonConfig, BalloonError> {
        if let Some(busdev) = self.get_bus_device(DeviceType::Virtio(TYPE_BALLOON), BALLOON_DEV_ID)
        {
            let virtio_device = busdev
                .lock()
                .expect("Poisoned lock")
                .mmio_transport_ref()
                .expect("Unexpected device type")
                .device();

            let config = virtio_device
                .lock()
                .expect("Poisoned lock")
                .as_mut_any()
                .downcast_mut::<Balloon>()
                .unwrap()
                .config();

            Ok(config)
        } else {
            Err(BalloonError::DeviceNotFound)
        }
    }

    /// Returns the latest balloon statistics if they are enabled.
    pub fn latest_balloon_stats(&self) -> Result<BalloonStats, BalloonError> {
        if let Some(busdev) = self.get_bus_device(DeviceType::Virtio(TYPE_BALLOON), BALLOON_DEV_ID)
        {
            let virtio_device = busdev
                .lock()
                .expect("Poisoned lock")
                .mmio_transport_ref()
                .expect("Unexpected device type")
                .device();

            let latest_stats = virtio_device
                .lock()
                .expect("Poisoned lock")
                .as_mut_any()
                .downcast_mut::<Balloon>()
                .unwrap()
                .latest_stats()
                .ok_or(BalloonError::StatisticsDisabled)
                .map(|stats| stats.clone())?;

            Ok(latest_stats)
        } else {
            Err(BalloonError::DeviceNotFound)
        }
    }

    /// Updates configuration for the balloon device target size.
    pub fn update_balloon_config(&mut self, amount_mib: u32) -> Result<(), BalloonError> {
        // The balloon cannot have a target size greater than the size of
        // the guest memory.
        if u64::from(amount_mib) > mem_size_mib(self.guest_memory()) {
            return Err(BalloonError::TooManyPagesRequested);
        }

        if let Some(busdev) = self.get_bus_device(DeviceType::Virtio(TYPE_BALLOON), BALLOON_DEV_ID)
        {
            {
                let virtio_device = busdev
                    .lock()
                    .expect("Poisoned lock")
                    .mmio_transport_ref()
                    .expect("Unexpected device type")
                    .device();

                virtio_device
                    .lock()
                    .expect("Poisoned lock")
                    .as_mut_any()
                    .downcast_mut::<Balloon>()
                    .unwrap()
                    .update_size(amount_mib)?;

                Ok(())
            }
        } else {
            Err(BalloonError::DeviceNotFound)
        }
    }

    /// Updates configuration for the balloon device as described in `balloon_stats_update`.
    pub fn update_balloon_stats_config(
        &mut self,
        stats_polling_interval_s: u16,
    ) -> Result<(), BalloonError> {
        if let Some(busdev) = self.get_bus_device(DeviceType::Virtio(TYPE_BALLOON), BALLOON_DEV_ID)
        {
            {
                let virtio_device = busdev
                    .lock()
                    .expect("Poisoned lock")
                    .mmio_transport_ref()
                    .expect("Unexpected device type")
                    .device();

                virtio_device
                    .lock()
                    .expect("Poisoned lock")
                    .as_mut_any()
                    .downcast_mut::<Balloon>()
                    .unwrap()
                    .update_stats_polling_interval(stats_polling_interval_s)?;
            }
            Ok(())
        } else {
            Err(BalloonError::DeviceNotFound)
        }
    }

    /// Signals Vmm to stop and exit.
    pub fn stop(&mut self, exit_code: FcExitCode) {
        // To avoid cycles, all teardown paths take the following route:
        //   +------------------------+----------------------------+------------------------+
        //   |        Vmm             |           Action           |           Vcpu         |
        //   +------------------------+----------------------------+------------------------+
        // 1 |                        |                            | vcpu.exit(exit_code)   |
        // 2 |                        |                            | vcpu.exit_evt.write(1) |
        // 3 |                        | <--- EventFd::exit_evt --- |                        |
        // 4 | vmm.stop()             |                            |                        |
        // 5 |                        | --- VcpuEvent::Finish ---> |                        |
        // 6 |                        |                            | StateMachine::finish() |
        // 7 | VcpuHandle::join()     |                            |                        |
        // 8 | vmm.shutdown_exit_code becomes Some(exit_code) breaking the main event loop  |
        //   +------------------------+----------------------------+------------------------+
        // Vcpu initiated teardown starts from `fn Vcpu::exit()` (step 1).
        // Vmm initiated teardown starts from `pub fn Vmm::stop()` (step 4).
        // Once `vmm.shutdown_exit_code` becomes `Some(exit_code)`, it is the upper layer's
        // responsibility to break main event loop and propagate the exit code value.
        info!("Vmm is stopping.");

        // We send a "Finish" event.  If a VCPU has already exited, this is the only
        // message it will accept... but running and paused will take it as well.
        // It breaks out of the state machine loop so that the thread can be joined.
        for (idx, handle) in self.vcpus_handles.iter().enumerate() {
            if let Err(err) = handle.send_event(VcpuEvent::Finish) {
                error!("Failed to send VcpuEvent::Finish to vCPU {}: {}", idx, err);
            }
        }
        // The actual thread::join() that runs to release the thread's resource is done in
        // the VcpuHandle's Drop trait.  We can trigger that to happen now by clearing the
        // list of handles. Do it here instead of Vmm::Drop to avoid dependency cycles.
        // (Vmm's Drop will also check if this list is empty).
        self.vcpus_handles.clear();

        // Break the main event loop, propagating the Vmm exit-code.
        self.shutdown_exit_code = Some(exit_code);
    }
}


