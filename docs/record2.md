[ 1690.032270] [ata_build_rw_tf][755] show stacktrace:
[ 1690.032278] CPU: 1 PID: 102 Comm: kworker/1:1H Not tainted 5.3.0 #95
[ 1690.032281] Hardware name: ARM Juno development board (r2) (DT)
[ 1690.032296] Workqueue: kblockd blk_mq_requeue_work
[ 1690.032301] Call trace:
[ 1690.032307]  dump_backtrace+0x0/0x150
[ 1690.032311]  show_stack+0x28/0x38
[ 1690.032319]  dump_stack+0xb8/0xfc
[ 1690.032325]  ata_build_rw_tf+0x31c/0x360
[ 1690.032330]  ata_scsi_rw_xlat+0x1b4/0x2c8
[ 1690.032334]  ata_scsi_translate+0x118/0x1d8
[ 1690.032337]  ata_scsi_queuecmd+0xa8/0x2f0
[ 1690.032342]  scsi_queue_rq+0x564/0x848
[ 1690.032346]  blk_mq_dispatch_rq_list+0xb0/0x508
[ 1690.032352]  blk_mq_sched_dispatch_requests+0x100/0x190
[ 1690.032356]  __blk_mq_run_hw_queue+0xb8/0x130
[ 1690.032361]  __blk_mq_delay_run_hw_queue+0x1ec/0x208
[ 1690.032365]  blk_mq_run_hw_queue+0xb0/0x108
[ 1690.032368]  blk_mq_run_hw_queues+0x48/0x68
[ 1690.032373]  blk_mq_requeue_work+0x150/0x180
[ 1690.032378]  process_one_work+0x1dc/0x450
[ 1690.032381]  worker_thread+0x54/0x410
[ 1690.032386]  kthread+0x108/0x138
[ 1690.032391]  ret_from_fork+0x10/0x18
[ 1690.032397] [ata_build_rw_tf][757] block: 0x0, n_block: 0x2, tf_flags: 8, tag: 0xd, class: 0x0, dev->no: 0, dev->ap->no: 0.
[ 1690.032406] [ata_build_rw_tf][861] tf->command = 0x61, tf->flags = 0x1f, tf->nsect = 0x68, tf->feature = 0x2, tf->lbal = 0x0, tf->lbam = 0x0, tf->lbah = 0x0, tf->device = 0x40, tf->hob_nsect = 0x0,
[ 1690.032406]  tf->hob_feature = 0x0, tf->hob_lbal = 0x0, tf->hob_lbam = 0x0, tf->hob_lbah = 0x0, tf->protocol = 0x6, tf->flags = 0x1f.
[ 1690.032412] [sil24_qc_prep][845] show stacktrace:
[ 1690.032416] CPU: 1 PID: 102 Comm: kworker/1:1H Not tainted 5.3.0 #95
[ 1690.032419] Hardware name: ARM Juno development board (r2) (DT)
[ 1690.032425] Workqueue: kblockd blk_mq_requeue_work
[ 1690.032428] Call trace:
[ 1690.032432]  dump_backtrace+0x0/0x150
[ 1690.032436]  show_stack+0x28/0x38
[ 1690.032440]  dump_stack+0xb8/0xfc
[ 1690.032445]  sil24_qc_prep+0x170/0x178
[ 1690.032449]  ata_qc_issue+0x14c/0x2c0
[ 1690.032454]  ata_scsi_translate+0xcc/0x1d8
[ 1690.032457]  ata_scsi_queuecmd+0xa8/0x2f0
[ 1690.032461]  scsi_queue_rq+0x564/0x848
[ 1690.032465]  blk_mq_dispatch_rq_list+0xb0/0x508
[ 1690.032470]  blk_mq_sched_dispatch_requests+0x100/0x190
[ 1690.032474]  __blk_mq_run_hw_queue+0xb8/0x130
[ 1690.032478]  __blk_mq_delay_run_hw_queue+0x1ec/0x208
[ 1690.032482]  blk_mq_run_hw_queue+0xb0/0x108
[ 1690.032486]  blk_mq_run_hw_queues+0x48/0x68
[ 1690.032490]  blk_mq_requeue_work+0x150/0x180
[ 1690.032494]  process_one_work+0x1dc/0x450
[ 1690.032498]  worker_thread+0x54/0x410
[ 1690.032503]  kthread+0x108/0x138
[ 1690.032507]  ret_from_fork+0x10/0x18
[ 1690.032511] [sil24_qc_issue][897] show stacktrace:
[ 1690.032515] CPU: 1 PID: 102 Comm: kworker/1:1H Not tainted 5.3.0 #95
[ 1690.032518] Hardware name: ARM Juno development board (r2) (DT)
[ 1690.032523] Workqueue: kblockd blk_mq_requeue_work
[ 1690.032527] Call trace:
[ 1690.032530]  dump_backtrace+0x0/0x150
[ 1690.032534]  show_stack+0x28/0x38
[ 1690.032538]  dump_stack+0xb8/0xfc
[ 1690.032542]  sil24_qc_issue+0x128/0x190
[ 1690.032547]  ata_qc_issue+0x174/0x2c0
[ 1690.032551]  ata_scsi_translate+0xcc/0x1d8
[ 1690.032555]  ata_scsi_queuecmd+0xa8/0x2f0
[ 1690.032558]  scsi_queue_rq+0x564/0x848
[ 1690.032562]  blk_mq_dispatch_rq_list+0xb0/0x508
[ 1690.032567]  blk_mq_sched_dispatch_requests+0x100/0x190
[ 1690.032571]  __blk_mq_run_hw_queue+0xb8/0x130
[ 1690.032575]  __blk_mq_delay_run_hw_queue+0x1ec/0x208
[ 1690.032579]  blk_mq_run_hw_queue+0xb0/0x108
[ 1690.032583]  blk_mq_run_hw_queues+0x48/0x68
[ 1690.032587]  blk_mq_requeue_work+0x150/0x180
[ 1690.032591]  process_one_work+0x1dc/0x450
[ 1690.032595]  worker_thread+0x54/0x410
[ 1690.032600]  kthread+0x108/0x138
[ 1690.032604]  ret_from_fork+0x10/0x18
[ 1690.032609] [sata_sil24.c][sil24_qc_issue][916]writel phys_addr: 0x811ddc68, val: 0xf904d000.
[ 1690.032612] [sata_sil24.c][sil24_qc_issue][917]writel phys_addr: 0x811ddc6c, val: 0x0.
[ 1690.252242] [sata_sil24.c][sil24_interrupt][1165]readl phys_addr: 0x810aa044.
[ 1690.261842] [sata_sil24.c][sil24_host_intr][1131]readl phys_addr: 0x811dd800.
write 1024 bytes.
[ 1690.275238] [sil24_qc_prep][845] show stacktrace:

[ 1690.275374] scmi-cpufreq scmi_dev.2: message for 0 is not expected!
[ 1690.287506] CPU: 1 PID: 102 Comm: kworker/1:1H Not tainted 5.3.0 #95
[ 1690.294307] Hardware name: ARM Juno development board (r2) (DT)
[ 1690.294318] Workqueue: kblockd blk_mq_requeue_work
[ 1690.302585] Call trace:
[ 1690.302594]  dump_backtrace+0x0/0x150
[ 1690.314734]  show_stack+0x28/0x38
[ 1690.321882]  dump_stack+0xb8/0xfc
[ 1690.321891]  sil24_qc_prep+0x170/0x178
[ 1690.332060]  ata_qc_issue+0x14c/0x2c0
[ 1690.339464]  ata_scsi_translate+0xcc/0x1d8
[ 1690.339472]  ata_scsi_queuecmd+0xa8/0x2f0
[ 1690.347486]  scsi_queue_rq+0x564/0x848
[ 1690.355665]  blk_mq_dispatch_rq_list+0xb0/0x508
[ 1690.355675]  blk_mq_sched_dispatch_requests+0x100/0x190
[ 1690.365150]  __blk_mq_run_hw_queue+0xb8/0x130
[ 1690.374188]  __blk_mq_delay_run_hw_queue+0x1ec/0x208
[ 1690.374196]  blk_mq_run_hw_queue+0xb0/0x108
[ 1690.382555]  blk_mq_run_hw_queues+0x48/0x68
[ 1690.390132]  blk_mq_requeue_work+0x150/0x180
[ 1690.390140]  process_one_work+0x1dc/0x450
[ 1690.396864]  worker_thread+0x54/0x410
[ 1690.413128]  kthread+0x108/0x138
[ 1690.413137]  ret_from_fork+0x10/0x18
[ 1690.426224] [sil24_qc_issue][897] show stacktrace:
[ 1690.442401] CPU: 1 PID: 102 Comm: kworker/1:1H Not tainted 5.3.0 #95
[ 1690.442409] Hardware name: ARM Juno development board (r2) (DT)
[ 1690.454468] Workqueue: kblockd blk_mq_requeue_work
[ 1690.467717] Call trace:
[ 1690.467726]  dump_backtrace+0x0/0x150
[ 1690.481158]  show_stack+0x28/0x38
[ 1690.494842]  dump_stack+0xb8/0xfc
[ 1690.494851]  sil24_qc_issue+0x128/0x190
[ 1690.507940]  ata_qc_issue+0x174/0x2c0
[ 1690.521622]  ata_scsi_translate+0xcc/0x1d8
[ 1690.521630]  ata_scsi_queuecmd+0xa8/0x2f0
[ 1690.534203]  scsi_queue_rq+0x564/0x848
[ 1690.548144]  blk_mq_dispatch_rq_list+0xb0/0x508
[ 1690.548154]  blk_mq_sched_dispatch_requests+0x100/0x190
[ 1690.563650]  __blk_mq_run_hw_queue+0xb8/0x130
[ 1690.576386]  __blk_mq_delay_run_hw_queue+0x1ec/0x208
[ 1690.576394]  blk_mq_run_hw_queue+0xb0/0x108
[ 1690.589139]  blk_mq_run_hw_queues+0x48/0x68
[ 1690.602391]  blk_mq_requeue_work+0x150/0x180
[ 1690.602400]  process_one_work+0x1dc/0x450
[ 1690.616520]  worker_thread+0x54/0x410
[ 1690.629085]  kthread+0x108/0x138
[ 1690.629094]  ret_from_fork+0x10/0x18
[ 1690.643043] [sata_sil24.c][sil24_qc_issue][916]writel phys_addr: 0x811ddc70, val: 0xf904e000.
[ 1690.655607] [sata_sil24.c][sil24_qc_issue][917]writel phys_addr: 0x811ddc74, val: 0x0.
[ 1690.668282] [sata_sil24.c][sil24_interrupt][1165]readl phys_addr: 0x810aa044.
[ 1690.683532] [sata_sil24.c][sil24_host_intr][1131]readl phys_addr: 0x811dd800.
[ 1690.709578] [sil24_qc_prep][845] show stacktrace:
[ 1690.709597] CPU: 2 PID: 103 Comm: kworker/2:1H Not tainted 5.3.0 #95
[ 1690.709602] Hardware name: ARM Juno development board (r2) (DT)
[ 1690.709615] Workqueue: kblockd blk_mq_requeue_work
[ 1690.709621] Call trace:
[ 1690.709629]  dump_backtrace+0x0/0x150
[ 1690.709635]  show_stack+0x28/0x38
[ 1690.709644]  dump_stack+0xb8/0xfc
[ 1690.709651]  sil24_qc_prep+0x170/0x178
[ 1690.709658]  ata_qc_issue+0x14c/0x2c0
[ 1690.709666]  ata_scsi_translate+0xcc/0x1d8
[ 1690.709671]  ata_scsi_queuecmd+0xa8/0x2f0
[ 1690.709677]  scsi_queue_rq+0x564/0x848
[ 1690.709684]  blk_mq_dispatch_rq_list+0xb0/0x508
[ 1690.709692]  blk_mq_sched_dispatch_requests+0x100/0x190
[ 1690.709699]  __blk_mq_run_hw_queue+0xb8/0x130
[ 1690.709705]  __blk_mq_delay_run_hw_queue+0x1ec/0x208
[ 1690.709712]  blk_mq_run_hw_queue+0xb0/0x108
[ 1690.709718]  blk_mq_run_hw_queues+0x48/0x68
[ 1690.709724]  blk_mq_requeue_work+0x150/0x180
[ 1690.709731]  process_one_work+0x1dc/0x450
[ 1690.709737]  worker_thread+0x54/0x410
[ 1690.709745]  kthread+0x108/0x138
[ 1690.709752]  ret_from_fork+0x10/0x18
[ 1690.709759] [sil24_qc_issue][897] show stacktrace:
[ 1690.709772] CPU: 2 PID: 103 Comm: kworker/2:1H Not tainted 5.3.0 #95
[ 1690.709780] Hardware name: ARM Juno development board (r2) (DT)
[ 1690.709793] Workqueue: kblockd blk_mq_requeue_work
[ 1690.709803] Call trace:
[ 1690.709813]  dump_backtrace+0x0/0x150
[ 1690.709822]  show_stack+0x28/0x38
[ 1690.709835]  dump_stack+0xb8/0xfc
[ 1690.709844]  sil24_qc_issue+0x128/0x190
[ 1690.709854]  ata_qc_issue+0x174/0x2c0
[ 1690.709864]  ata_scsi_translate+0xcc/0x1d8
[ 1690.709872]  ata_scsi_queuecmd+0xa8/0x2f0
[ 1690.709882]  scsi_queue_rq+0x564/0x848
[ 1690.709893]  blk_mq_dispatch_rq_list+0xb0/0x508
[ 1690.709905]  blk_mq_sched_dispatch_requests+0x100/0x190
[ 1690.709914]  __blk_mq_run_hw_queue+0xb8/0x130
[ 1690.709924]  __blk_mq_delay_run_hw_queue+0x1ec/0x208
[ 1690.709934]  blk_mq_run_hw_queue+0xb0/0x108
[ 1690.709943]  blk_mq_run_hw_queues+0x48/0x68
[ 1690.709953]  blk_mq_requeue_work+0x150/0x180
[ 1690.709963]  process_one_work+0x1dc/0x450
[ 1690.709973]  worker_thread+0x54/0x410
[ 1690.709984]  kthread+0x108/0x138
[ 1690.709993]  ret_from_fork+0x10/0x18
[ 1690.710003] [sata_sil24.c][sil24_qc_issue][916]writel phys_addr: 0x811ddce0, val: 0xf905c000.
[ 1690.710012] [sata_sil24.c][sil24_qc_issue][917]writel phys_addr: 0x811ddce4, val: 0x0.
[ 1690.716099] [sata_sil24.c][sil24_interrupt][1165]readl phys_addr: 0x810aa044.
[ 1690.729687] [sata_sil24.c][sil24_host_intr][1131]readl phys_addr: 0x811dd800.
[ 1690.756233] [hhkr_ctl_ioctl][135] hitchhiker-ctl: update debug_record_sata to 0.
>>>
|||








[ 1691.895727] [hhkr_ctl_ioctl][135] hitchhiker-ctl: update debug_record_sata to 1.
[ 1691.904860] [ata_build_rw_tf][755] show stacktrace:
[ 1691.904866] CPU: 1 PID: 102 Comm: kworker/1:1H Not tainted 5.3.0 #95
[ 1691.904868] Hardware name: ARM Juno development board (r2) (DT)
[ 1691.904879] Workqueue: kblockd blk_mq_run_work_fn
[ 1691.904883] Call trace:
[ 1691.904888]  dump_backtrace+0x0/0x150
[ 1691.904891]  show_stack+0x28/0x38
[ 1691.904897]  dump_stack+0xb8/0xfc
[ 1691.904902]  ata_build_rw_tf+0x31c/0x360
[ 1691.904907]  ata_scsi_rw_xlat+0x1b4/0x2c8
[ 1691.904911]  ata_scsi_translate+0x118/0x1d8
[ 1691.904913]  ata_scsi_queuecmd+0xa8/0x2f0
[ 1691.904917]  scsi_queue_rq+0x564/0x848
[ 1691.904921]  blk_mq_dispatch_rq_list+0xb0/0x508
[ 1691.904926]  blk_mq_do_dispatch_sched+0x6c/0x110
[ 1691.904930]  blk_mq_sched_dispatch_requests+0x140/0x190
[ 1691.904934]  __blk_mq_run_hw_queue+0xb8/0x130
[ 1691.904937]  blk_mq_run_work_fn+0x2c/0x38
[ 1691.904942]  process_one_work+0x1dc/0x450
[ 1691.904945]  worker_thread+0x54/0x410
[ 1691.904949]  kthread+0x108/0x138
[ 1691.904953]  ret_from_fork+0x10/0x18
[ 1691.904958] [ata_build_rw_tf][757] block: 0x0, n_block: 0x8, tf_flags: 0, tag: 0xd, class: 0x0, dev->no: 0, dev->ap->no: 0.
[ 1691.904966] [ata_build_rw_tf][861] tf->command = 0x60, tf->flags = 0x17, tf->nsect = 0x68, tf->feature = 0x8, tf->lbal = 0x0, tf->lbam = 0x0, tf->lbah = 0x0, tf->device = 0x40, tf->hob_nsect = 0x0,
[ 1691.904966]  tf->hob_feature = 0x0, tf->hob_lbal = 0x0, tf->hob_lbam = 0x0, tf->hob_lbah = 0x0, tf->protocol = 0x6, tf->flags = 0x17.
[ 1691.904970] [sil24_qc_prep][845] show stacktrace:
root@genericarmv8:/data# [ 1691.904973] CPU: 1 PID: 102 Comm: kworker/1:1H Not tainted 5.3.0 #95
[ 1691.904976] Hardware name: ARM Juno development board (r2) (DT)
[ 1691.904980] Workqueue: kblockd blk_mq_run_work_fn
[ 1691.904983] Call trace:
[ 1691.904986]  dump_backtrace+0x0/0x150
[ 1691.904990]  show_stack+0x28/0x38
[ 1691.904994]  dump_stack+0xb8/0xfc
[ 1691.904998]  sil24_qc_prep+0x170/0x178
[ 1691.905001]  ata_qc_issue+0x14c/0x2c0
[ 1691.905005]  ata_scsi_translate+0xcc/0x1d8
[ 1691.905008]  ata_scsi_queuecmd+0xa8/0x2f0
[ 1691.905011]  scsi_queue_rq+0x564/0x848
[ 1691.905015]  blk_mq_dispatch_rq_list+0xb0/0x508
[ 1691.905019]  blk_mq_do_dispatch_sched+0x6c/0x110
[ 1691.905023]  blk_mq_sched_dispatch_requests+0x140/0x190
[ 1691.905026]  __blk_mq_run_hw_queue+0xb8/0x130
[ 1691.905030]  blk_mq_run_work_fn+0x2c/0x38
[ 1691.905033]  process_one_work+0x1dc/0x450
[ 1691.905036]  worker_thread+0x54/0x410
[ 1691.905040]  kthread+0x108/0x138
[ 1691.905043]  ret_from_fork+0x10/0x18
[ 1691.905047] [sil24_qc_issue][897] show stacktrace:
[ 1691.905051] CPU: 1 PID: 102 Comm: kworker/1:1H Not tainted 5.3.0 #95
[ 1691.905053] Hardware name: ARM Juno development board (r2) (DT)
[ 1691.905057] Workqueue: kblockd blk_mq_run_work_fn
[ 1691.905060] Call trace:
[ 1691.905063]  dump_backtrace+0x0/0x150
[ 1691.905066]  show_stack+0x28/0x38
[ 1691.905070]  dump_stack+0xb8/0xfc
[ 1691.905073]  sil24_qc_issue+0x128/0x190
[ 1691.905077]  ata_qc_issue+0x174/0x2c0
[ 1691.905081]  ata_scsi_translate+0xcc/0x1d8
[ 1691.905084]  ata_scsi_queuecmd+0xa8/0x2f0
[ 1691.905086]  scsi_queue_rq+0x564/0x848
[ 1691.905090]  blk_mq_dispatch_rq_list+0xb0/0x508
[ 1691.905094]  blk_mq_do_dispatch_sched+0x6c/0x110
[ 1691.905098]  blk_mq_sched_dispatch_requests+0x140/0x190
[ 1691.905101]  __blk_mq_run_hw_queue+0xb8/0x130
[ 1691.905105]  blk_mq_run_work_fn+0x2c/0x38
[ 1691.905108]  process_one_work+0x1dc/0x450
[ 1691.905111]  worker_thread+0x54/0x410
[ 1691.905115]  kthread+0x108/0x138
[ 1691.905118]  ret_from_fork+0x10/0x18
[ 1691.905122] [sata_sil24.c][sil24_qc_issue][916]writel phys_addr: 0x811ddc68, val: 0xf904d000.
[ 1691.905125] [sata_sil24.c][sil24_qc_issue][917]writel phys_addr: 0x811ddc6c, val: 0x0.
[ 1691.917177] [sata_sil24.c][sil24_interrupt][1165]readl phys_addr: 0x810aa044.
[ 1691.928453] [sata_sil24.c][sil24_host_intr][1131]readl phys_addr: 0x811dd800.
[ 1691.945358] [hhkr_ctl_ioctl][135] hitchhiker-ctl: update debug_record_sata to 0.