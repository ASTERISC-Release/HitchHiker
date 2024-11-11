### Record phase on FVP

```
ksys_write // read_write.c
|.vfs_write
  |.__vfs_write
    |.new_sync_write(file, p, count, pos)
      |.init_sync_kiocb(&kiocb, filp)  
      |.iov_iter_init(&iter, WRITE, &iov, 1, len)
      |.call_write_iter(filp, &kiocb, &iter)  // fs.h
        |.file->f_op->write_iter(kio, iter)
         =blkdev_write_iter(iocb, from)  // block_dev.c
          |.blk_start_plug(&plug)
          |.__generic_file_write_iter(iocb, from)
            |.generic_file_direct_write(iocb, from)  // filemap.c
              |.filemap_write_and_wait_range(mapping, pos, pos + write_len - 1) 
                |.mapping_needs_writeback(mapping)
              |.mapping->a_ops->direct_IO(iocb, from)
               =blkdev_direct_IO(iocb, iter)  // block_dev.c
                    ｜
                    ｜
                    ｜
 _ _ _ _ _ _ _ _ _ _｜
|
blkdev_direct_IO(iocb, iter)  // block_dev.c
|.__blkdev_direct_IO_simple(iocb, iter, nr_pages)
  /* block_device *bdev = I_BDEV(bdev_file_inode(file))
     struct bio bio;
  |.bio_init(&bio, vecs, nr_pages)
  |.bio_set_dev(&bio, bdev)
  |.bio_iov_iter_get_pages(&bio, iter)         /* iter to bio */
    |.__bio_iov_iter_get_pages(bio, iter)
      /* bio->bi_io_vec;  bio->bi_vcnt
  |.dio_bio_write_op(iocb)
  |.submit_bio(&bio)    // blk-core.c
    |.generic_make_request(bio)                                  /* FS -> bio */ ****IMPORTANT!****
      |.q->make_request_fn(q, bio)
       =blk_mq_make_request(q, bio)  // blk-mq.c   /* Request layer: multiqueue */ ****IMPORTANT!****  
        |. request *rq = blk_mq_get_request((request_queue *)q, bio, &data)

        |.blk_mq_bio_to_request(rq, bio, nr_segs)
        

    |.io_schedule()    // core.c                /* schedule! */  ****IMPORTANT!****
      |.io_schedule_prepare()
        |.blk_schedule_flush_plug(current)
          |.blk_flush_plug_list(plug, true)    // blkdev.h
            |.blk_mq_flush_plug_list(plug, from_schedule)  // blk-core.c
              |.blk_mq_sched_insert_requests(hctx, ctx, list, run_queue_async)  // blk-mq-sched.c
                |.blk_mq_run_hw_queue(hctx, async)     // blk-mq.c          ****IMPORTANT!****
                  |.__blk_mq_delay_run_hw_queue(hctx, async, 0)
                    |.kblockd_mod_delayed_work_on(cpu, dwork, delay)
                      |.mod_delayed_work_on(cpu, kblockd_workqueue, dwork, delay)  // workqueue.c
                        |....
( see this ref https://blog.csdn.net/hu1610552336/article/details/111464548 )
...
blk_mq_run_work_fn
|.__blk_mq_run_hw_queue
  |.blk_mq_sched_dispatch_requests(hctx)  // blk-mq-sched.c       **IMPORTANT!**
    |.blk_mq_do_dispatch_sched(hctx)    // blk-mq-sched.c 
      |.blk_mq_dispatch_rq_list(q, list, got_budget) // blk-mq.c
        /* struct blk_mq_queue_data bd;
           request *rq = list_first_entry();
           |.blk_mq_get_driver_tag(rq)
             /* struct blk_mq_alloc_data data = {...};
                rq->tag = blk_mq_get_tag(&data);
        |.q->mq_ops->queue_rq(hctx, &bd)
         =scsi_queue_rq(hctx, bd)     // scsi_lib.c         **REACH SCSI!!!!**
 _ _ _ _ _ _ _ _ _ _｜
|
scsi_queue_rq(hctx, bd)

/* scsi_cmnd *cmd = blk_mq_rq_to_pdu((request *)bd->rq) <== (request *)bd->rq + 1 !!

|.scsi_dispatch_cmd(cmd)

  /* struct Scsi_Host *host = cmd->(scsi_device *)device->host; 

  |.host->hostt->queuecommand(host, cmd)
   =ata_scsi_queuecmd(shost, cmd)     // libata-scsi.c
    
.    /* ata_port *ap =ata_shost_to_port(shost) 
        ata_device *dev = ata_scsi_find_dev(ap, scsidev: cmd->device)
.
    |.__ata_scsi_queuecmd((scsi_cmnd *)scmd, (ata_device *)dev)
      |.ata_scsi_translate(dev, scmd, xlat_func)        /* ata_scsi_qc_new! */
 _ _ _ _ _ _ _ _ _ _｜
|
ata_scsi_translate((ata_device *)dev, (scsi_cmnd *)cmd, xlat_func)

/* ata_port *ap = dev->link->ap

|.ata_scsi_qc_new(dev, cmd) 
  |.ata_qc_new_init(dev, tag: cmd->(request *)request->tag)       // configure's tag
|.ata_sg_init(qc, scsi_sglist(cmd), scsi_sg_count(cmd)) 
|.xlat_func(qc)
 =ata_scsi_rw_xlat(qc)
  |.scsi_10_lba_len(cdb: scmd->cmnd, &block, &n_block)       /* case WRITE_10!
  |.ata_build_rw_tf(&qc->tf, (ata_device*)qc->dev, block, n_block, tf_flags, qc->hw_tag, class)  /**IMPORTANT taskfile tf!**/
|.ata_qc_issue(qc)
  |.ata_sg_setup(qc)  /* ?? */
    |.dma_map_sg(qc->ap->dev, qc->sg, qc->n_elem, qc->dma_dir)
      |.iommu_dma_map_sg
  |.ap->ops->qc_prep(qc)
   =ahci_qc_prep(qc) /****CONFIG cmd_tbl!****/
    |.ata_tf_to_fis(tf: &qc->tf, pmp: c->dev->link->pmp, 1, fis: cmd_tbl)
    |.ahci_fill_sg(qc, cmd_tbl)
    |.ahci_fill_cmd_slot(pp, qc->hw_tag, opts)
  |.ahci_qc_issue(qc)

// IRQ
ahci_single_level_irq_intr /****FINISH!!!****/  // just hook there right now!
|.ahci_handle_port_intr(host, irq_masked)
  |.ahci_handle_port_interrupt(ap, port_mmio, status)
   |.ata_qc_complete_multiple
     |.ata_qc_complete
```