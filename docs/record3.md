=ata_scsi_rw_xlat(qc)
  |.scsi_10_lba_len(cdb: scmd->cmnd, &block, &n_block)       /* case WRITE_10!
  |.ata_build_rw_tf(&qc->tf, (ata_device*)qc->dev, block, n_block, tf_flags, qc->hw_tag, class)  /**IMPORTANT taskfile tf!**/
|.ata_qc_issue(qc)
  |.ata_sg_setup(qc)  /* ?? */
    |.dma_map_sg(qc->ap->dev, qc->sg, qc->n_elem, qc->dma_dir)  // direct DMA!!!
  |.ap->ops->qc_prep(qc)
   =sil24_qc_prep(qc) /****CONFIG prb sge!****/
    |.ata_tf_to_fis(tf: &qc->tf, pmp: c->dev->link->pmp, 1, fis: cmd_tbl)
    |.sil24_fill_sg(qc, cmd_tbl)
    <!-- |.ahci_fill_cmd_slot(pp, qc->hw_tag, opts) -->
  |.sil24_qc_issue(qc)

// IRQ
ahci_single_level_irq_intr /****FINISH!!!****/  // just hook there right now!
|.ahci_handle_port_intr(host, irq_masked)
  |.ahci_handle_port_interrupt(ap, port_mmio, status)
   |.ata_qc_complete_multiple
     |.ata_qc_complete





[ 2654.410837] [hhkr_ctl_ioctl][135] hitchhiker-ctl: update debug_record_sata to 1.
buf addr: 0x5584f1ec00.
<<<
[ 2654.495454] [ata_build_rw_tf][755] show stacktrace:
[ 2654.534658] Call trace:
[ 2654.547920]  dump_backtrace+0x0/0x150
[ 2654.547927]  show_stack+0x28/0x38
[ 2654.561017]  dump_stack+0xb8/0xfc
[ 2654.561027]  ata_build_rw_tf+0x31c/0x360
[ 2654.574112]  ata_scsi_rw_xlat+0x1b4/0x2c8
[ 2654.574121]  ata_scsi_translate+0x118/0x1d8
[ 2654.587635]  ata_scsi_queuecmd+0xa8/0x2f0
[ 2654.587643]  scsi_queue_rq+0x564/0x848
[ 2654.599009]  blk_mq_dispatch_rq_list+0xb0/0x508
[ 2654.599018]  blk_mq_sched_dispatch_requests+0x100/0x190
[ 2654.611414]  __blk_mq_run_hw_queue+0xb8/0x130
[ 2654.611422]  __blk_mq_delay_run_hw_queue+0x1ec/0x208
[ 2654.624851]  blk_mq_run_hw_queue+0xb0/0x108
[ 2654.624859]  blk_mq_run_hw_queues+0x48/0x68
[ 2654.639063]  blk_mq_requeue_work+0x150/0x180
[ 2654.639071]  process_one_work+0x1dc/0x450
[ 2654.654994]  worker_thread+0x54/0x410
[ 2654.655002]  kthread+0x108/0x138
[ 2654.669292]  ret_from_fork+0x10/0x18
[ 2654.669301] [ata_build_rw_tf][757] block: 0x0, n_block: 0x2, tf_flags: 8, tag: 0xe, class: 0x0, dev->no: 0, dev->ap->no: 0.
[ 2654.684799] [ata_build_rw_tf][861] tf->command = 0x61, tf->flags = 0x1f, tf->nsect = 0x70, tf->feature = 0x2, tf->lbal = 0x0, tf->lbam = 0x0, tf->lbah = 0x0, tf->device = 0x40, tf->hob_nsect = 0x0,
[ 2654.684799]  tf->hob_feature = 0x0, tf->hob_lbal = 0x0, tf->hob_lbam = 0x0, tf->hob_lbah = 0x0, tf->protocol = 0x6, tf->flags = 0x1f.
[ 2654.684806] [sil24_qc_prep][845] show stacktrace:
[ 2654.715025] Hardware name: ARM Juno development board (r2) (DT)
[ 2654.715033] Workqueue: kblockd blk_mq_requeue_work
[ 2654.729493] Call trace:
[ 2654.756626]  sil24_qc_prep+0x170/0x178
[ 2654.756634]  <ata_qc_issue+0x14c/0x2c0>
[ 2654.772559]  ata_scsi_translate+0xcc/0x1d8
[ 2654.772566]  ata_scsi_queuecmd+0xa8/0x2f0
[ 2654.785394]  scsi_queue_rq+0x564/0x848
[ 2654.785402]  blk_mq_dispatch_rq_list+0xb0/0x508
[ 2654.799692]  blk_mq_sched_dispatch_requests+0x100/0x190
[ 2654.799700]  __blk_mq_run_hw_queue+0xb8/0x130
[ 2654.815624]  __blk_mq_delay_run_hw_queue+0x1ec/0x208
[ 2654.815632]  blk_mq_run_hw_queue+0xb0/0x108
[ 2654.829921]  blk_mq_run_hw_queues+0x48/0x68
[ 2654.829929]  blk_mq_requeue_work+0x150/0x180
[ 2654.844219]  process_one_work+0x1dc/0x450
[ 2654.844226]  worker_thread+0x54/0x410
[ 2654.861355]  kthread+0x108/0x138
[ 2654.861363]  ret_from_fork+0x10/0x18
[ 2654.875658] [sil24_qc_issue][897] show stacktrace:
[ 2654.891582] CPU: 1 PID: 102 Comm: kworker/1:1H Not tainted 5.3.0 #95
[ 2654.891589] Hardware name: ARM Juno development board (r2) (DT)
[ 2654.905887] Workqueue: kblockd blk_mq_requeue_work
[ 2654.920174] Call trace:
[ 2654.920183]  dump_backtrace+0x0/0x150
[ 2654.936106]  show_stack+0x28/0x38
[ 2654.936115]  dump_stack+0xb8/0xfc
[ 2654.950404]  sil24_qc_issue+0x128/0x190
[ 2654.950412]  ata_qc_issue+0x174/0x2c0
[ 2654.966335]  ata_scsi_translate+0xcc/0x1d8
[ 2654.966343]  ata_scsi_queuecmd+0xa8/0x2f0
[ 2654.980633]  scsi_queue_rq+0x564/0x848
[ 2654.980641]  blk_mq_dispatch_rq_list+0xb0/0x508
[ 2654.994501]  blk_mq_sched_dispatch_requests+0x100/0x190
[ 2654.994509]  __blk_mq_run_hw_queue+0xb8/0x130
[ 2655.007939]  __blk_mq_delay_run_hw_queue+0x1ec/0x208
[ 2655.007947]  blk_mq_run_hw_queue+0xb0/0x108
[ 2655.020603]  blk_mq_run_hw_queues+0x48/0x68
[ 2655.020610]  blk_mq_requeue_work+0x150/0x180
[ 2655.031976]  process_one_work+0x1dc/0x450
[ 2655.031983]  worker_thread+0x54/0x410
[ 2655.045070]  kthread+0x108/0x138
[ 2655.045078]  ret_from_fork+0x10/0x18
[ 2655.058169] [sata_sil24.c][sil24_qc_issue][916]writel phys_addr: 0x811ddc70, val: 0xf904e000.
[ 2655.071255] [sata_sil24.c][sil24_qc_issue][917]writel phys_addr: 0x811ddc74, val: 0x0.
[ 2655.076026] [sata_sil24.c][sil24_interrupt][1165]readl phys_addr: 0x810aa044.
[ 2655.076038] [sata_sil24.c][sil24_host_intr][1131]readl phys_addr: 0x811dd800.
[ 2655.076087] [sil24_qc_prep][845] show stacktrace:
[ 2655.076092] CPU: 1 PID: 102 Comm: kworker/1:1H Not tainted 5.3.0 #95
[ 2655.076095] Hardware name: ARM Juno development board (r2) (DT)
[ 2655.076102] Workqueue: kblockd blk_mq_requeue_work
[ 2655.076105] Call trace:
[ 2655.076108]  dump_backtrace+0x0/0x150
[ 2655.076112]  show_stack+0x28/0x38
[ 2655.076116]  dump_stack+0xb8/0xfc
[ 2655.076119]  sil24_qc_prep+0x170/0x178
[ 2655.076123]  ata_qc_issue+0x14c/0x2c0
[ 2655.076127]  ata_scsi_translate+0xcc/0x1d8
[ 2655.076130]  ata_scsi_queuecmd+0xa8/0x2f0
[ 2655.076133]  scsi_queue_rq+0x564/0x848
[ 2655.076136]  blk_mq_dispatch_rq_list+0xb0/0x508
[ 2655.076140]  blk_mq_sched_dispatch_requests+0x100/0x190
[ 2655.076144]  __blk_mq_run_hw_queue+0xb8/0x130
[ 2655.076147]  __blk_mq_delay_run_hw_queue+0x1ec/0x208
[ 2655.076150]  blk_mq_run_hw_queue+0xb0/0x108
[ 2655.076154]  blk_mq_run_hw_queues+0x48/0x68
[ 2655.076157]  blk_mq_requeue_work+0x150/0x180
[ 2655.076161]  process_one_work+0x1dc/0x450
[ 2655.076164]  worker_thread+0x54/0x410
[ 2655.076168]  kthread+0x108/0x138
[ 2655.076171]  ret_from_fork+0x10/0x18
[ 2655.076174] [sil24_qc_issue][897] show stacktrace:
[ 2655.076178] CPU: 1 PID: 102 Comm: kworker/1:1H Not tainted 5.3.0 #95
[ 2655.076180] Hardware name: ARM Juno development board (r2) (DT)
[ 2655.076185] Workqueue: kblockd blk_mq_requeue_work
[ 2655.076188] Call trace:
[ 2655.076191]  dump_backtrace+0x0/0x150
[ 2655.076194]  show_stack+0x28/0x38
[ 2655.076198]  dump_stack+0xb8/0xfc
[ 2655.076201]  sil24_qc_issue+0x128/0x190
[ 2655.076205]  ata_qc_issue+0x174/0x2c0
[ 2655.076208]  ata_scsi_translate+0xcc/0x1d8
[ 2655.076211]  ata_scsi_queuecmd+0xa8/0x2f0
[ 2655.076214]  scsi_queue_rq+0x564/0x848
[ 2655.076217]  blk_mq_dispatch_rq_list+0xb0/0x508
[ 2655.076222]  blk_mq_sched_dispatch_requests+0x100/0x190
[ 2655.076225]  __blk_mq_run_hw_queue+0xb8/0x130
[ 2655.076228]  __blk_mq_delay_run_hw_queue+0x1ec/0x208
[ 2655.076232]  blk_mq_run_hw_queue+0xb0/0x108
[ 2655.076235]  blk_mq_run_hw_queues+0x48/0x68
[ 2655.076238]  blk_mq_requeue_work+0x150/0x180
[ 2655.076242]  process_one_work+0x1dc/0x450
[ 2655.076245]  worker_thread+0x54/0x410
[ 2655.076249]  kthread+0x108/0x138
[ 2655.076252]  ret_from_fork+0x10/0x18
[ 2655.076256] [sata_sil24.c][sil24_qc_issue][916]writel phys_addr: 0x811ddc78, val: 0xf904f000.
[ 2655.076260] [sata_sil24.c][sil24_qc_issue][917]writel phys_addr: 0x811ddc7c, val: 0x0.
[ 2655.076814] [sata_sil24.c][sil24_interrupt][1165]readl phys_addr: 0x810aa044.
[ 2655.076826] [sata_sil24.c][sil24_host_intr][1131]readl phys_addr: 0x811dd800.
[ 2655.076883] [sil24_qc_prep][845] show stacktrace:
[ 2655.076889] CPU: 2 PID: 103 Comm: kworker/2:1H Not tainted 5.3.0 #95
[ 2655.076893] Hardware name: ARM Juno development board (r2) (DT)
[ 2655.076900] Workqueue: kblockd blk_mq_requeue_work
[ 2655.076903] Call trace:
[ 2655.076907]  dump_backtrace+0x0/0x150
[ 2655.076910]  show_stack+0x28/0x38
[ 2655.076915]  dump_stack+0xb8/0xfc
[ 2655.076918]  sil24_qc_prep+0x170/0x178
[ 2655.076922]  ata_qc_issue+0x14c/0x2c0
[ 2655.076926]  ata_scsi_translate+0xcc/0x1d8
[ 2655.076929]  ata_scsi_queuecmd+0xa8/0x2f0
[ 2655.076932]  scsi_queue_rq+0x564/0x848
[ 2655.076936]  blk_mq_dispatch_rq_list+0xb0/0x508
[ 2655.076940]  blk_mq_sched_dispatch_requests+0x100/0x190
[ 2655.076944]  __blk_mq_run_hw_queue+0xb8/0x130
[ 2655.076947]  __blk_mq_delay_run_hw_queue+0x1ec/0x208
[ 2655.076951]  blk_mq_run_hw_queue+0xb0/0x108
[ 2655.076954]  blk_mq_run_hw_queues+0x48/0x68
[ 2655.076957]  blk_mq_requeue_work+0x150/0x180
[ 2655.076961]  process_one_work+0x1dc/0x450
[ 2655.076964]  worker_thread+0x54/0x410
[ 2655.076968]  kthread+0x108/0x138
[ 2655.076972]  ret_from_fork+0x10/0x18
[ 2655.076976] [sil24_qc_issue][897] show stacktrace:
[ 2655.076979] CPU: 2 PID: 103 Comm: kworker/2:1H Not tainted 5.3.0 #95
[ 2655.076981] Hardware name: ARM Juno development board (r2) (DT)
[ 2655.076986] Workqueue: kblockd blk_mq_requeue_work
[ 2655.076989] Call trace:
[ 2655.076993]  dump_backtrace+0x0/0x150
[ 2655.076996]  show_stack+0x28/0x38
[ 2655.077000]  dump_stack+0xb8/0xfc
[ 2655.077003]  sil24_qc_issue+0x128/0x190
[ 2655.077007]  ata_qc_issue+0x174/0x2c0
[ 2655.077013]  ata_scsi_translate+0xcc/0x1d8
[ 2655.077016]  ata_scsi_queuecmd+0xa8/0x2f0
[ 2655.077019]  scsi_queue_rq+0x564/0x848
[ 2655.077023]  blk_mq_dispatch_rq_list+0xb0/0x508
[ 2655.077027]  blk_mq_sched_dispatch_requests+0x100/0x190
[ 2655.077030]  __blk_mq_run_hw_queue+0xb8/0x130
[ 2655.077034]  __blk_mq_delay_run_hw_queue+0x1ec/0x208
[ 2655.077037]  blk_mq_run_hw_queue+0xb0/0x108
[ 2655.077040]  blk_mq_run_hw_queues+0x48/0x68
[ 2655.077044]  blk_mq_requeue_work+0x150/0x180
[ 2655.077047]  process_one_work+0x1dc/0x450
[ 2655.077050]  worker_thread+0x54/0x410
[ 2655.077054]  kthread+0x108/0x138
[ 2655.077058]  ret_from_fork+0x10/0x18
[ 2655.077062] [sata_sil24.c][sil24_qc_issue][916]writel phys_addr: 0x811ddce0, val: 0xf905c000.
[ 2655.077065] [sata_sil24.c][sil24_qc_issue][917]writel phys_addr: 0x811ddce4, val: 0x0.
[ 2655.077128] [sata_sil24.c][sil24_interrupt][1165]readl phys_addr: 0x810aa044.
[ 2655.077140] [sata_sil24.c][sil24_host_intr][1131]readl phys_addr: 0x811dd800.
[ 2655.099094] [hhkr_ctl_ioctl][135] hitchhiker-ctl: update debug_record_sata to 0.
>>>
|||
[ 2657.240242] [hhkr_ctl_ioctl][135] hitchhiker-ctl: update debug_record_sata to 1.
[ 2657.243194] [irq-gic.c][gic_cpu_if_up][476]readl phys_addr: 0x80002000.
[ 2657.248450] [hhkr_ctl_ioctl][135] hitchhiker-ctl: update debug_record_sata to 0.







[ata_build_rw_tf][761] block: 0x0, n_block: 0x2, tf_flags: 8, tag: 0x2, class: 0x0, dev->no: 0, dev->ap->no: 0.
[ata_build_rw_tf][865] tf->command = 0x61, tf->flags = 0x1f, tf->nsect = 0x10, [tf->feature = 0x2, tf->lbal = 0x0, tf->lbam = 0x0, tf->lbah = 0x0, tf->device = 0x40, tf->hob_nsect = 0x0,
[tf->hob_feature = 0x0, tf->hob_lbal = 0x0, tf->hob_lbam = 0x0, tf->hob_lbah = 0x0, tf->protocol = 0x6, tf->flags = 0x1f.
[ata_sg_setup][5082] dma_mapped_sg: qc->n_elem: 1, qc->dma_dir: 1, ret n_elem: 1.

[sil24_qc_prep][883] qc->flags: 0xb, pp->cmd_block addr: 0xffffffc079040000, prb->prot: 0x14, prb->ctrl: 0x1
[ata_tf_to_fis]
fis addr: 0xffffffc079042008, fis[0]: 0x27, fis[1]: 0x80, fis[2]: 0x61, fis[3]: 0x2, fis[4]: 0x0, fis[5]: 0x0, fis[6]: 0x0, fis[7]: 0x40, fis[8]: 0x0, fis[9]: 0x0, fis[10]: 0x0, fis[11]: 0x0, fis[12]: 0x10, fis[13]: 0x0, fis[14]: 0x0, fis[15]: 0x8, fis[16]: 0x0, fis[17]: 0x0, fis[18]: 0x0, fis[19]: 0x0.

[sata_sil24.c][sil24_qc_issue][914]writel phys_addr: 0x811ddc10, val: 0xf9042000.
[sata_sil24.c][sil24_qc_issue][915]writel phys_addr: 0x811ddc14, val: 0x0.


[sata_sil24.c][sil24_interrupt][1163]readl phys_addr: 0x810aa044.
[sata_sil24.c][sil24_host_intr][1129]readl phys_addr: 0x811dd800.

---------------------------------

[  208.477611] [hhkrd_secIO_init_plat][90] port_base_mmio_virt: 0xffffff80111dc000, port_base_mmio_phys: 0x811dc000.
[  208.487784] [hhkrd_secIO_init_juno][233] pp->cmd_block addr: 0xffffffc079040000, prb->prot: 0x14, prb->ctrl: 0x1

[fake_ata_build_rw_tf][43] tf->command = 0x61, tf->flags = 0x1f, tf->nsect = 0x10, tf->feature = 0x0, tf->lbal = 0x0, tf->lbam = 0x0, tf->lbah = 0x0, tf->device = 0x40, tf->hob_nsect = 0x0,
tf->hob_feature = 0x40, tf->hob_lbal = 0x0, tf->hob_lbam = 0x0, tf->hob_lbah = 0x0, tf->protocol = 0x6, tf->flags = 0x1f.
[fake_ata_tf_to_fis][78] 
fis addr: 0xffffffc079042008, fis[0]: 0x27, fis[1]: 0x80, fis[2]: 0x61, fis[3]: 0x0, fis[4]: 0x0, fis[5]: 0x0, fis[6]: 0x0, fis[7]: 0x40, fis[8]: 0x0, fis[9]: 0x0, fis[10]: 0x0, fis[11]: 0x40, fis[12]: 0x10, fis[13]: 0x0, fis[14]: 0x0, fis[15]: 0x0, fis[16]: 0x0, fis[17]: 0x0, fis[18]: 0x0, fis[19]: 0x0.
[hhkrd_secIO_assignjob_juno][289] 
paddr: 0xf9042000 (phys: 0xffffff80111ddc10), activate: 0x8169042000 (phys: 0x811ddc10).
