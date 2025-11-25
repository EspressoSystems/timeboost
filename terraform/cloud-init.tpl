#cloud-config
write_files:
  -encoding: gz+b64
   content: !!binary |
     ${timeboost_config}
   path: /etc/timeboost/timeboost.toml
   owner: ec2-user:ec2-user
   permissions: "0400"
   defer: true
  -encoding: gz+b64
   content: !!binary |
     ${nitro_config}
   path: /etc/nitro/sequencer_config.json
   owner: ec2-user:ec2-user
   permissions: "0400"
   defer: true
  # TODO: Remove when removing block-maker
  -encoding: gz+b64
   content: !!binary |
     ${chain_config}
   path: /etc/nitromeboost/chain.toml
   owner: ec2-user:ec2-user
   permissions: "0400"
   defer: true
