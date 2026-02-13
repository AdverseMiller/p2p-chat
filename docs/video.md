# Video (Linux, raw UDP P2P)

## Build deps
- `libavcodec`, `libavutil`, `libswscale`
- V4L2 headers (`linux/videodev2.h`)

On Debian/Ubuntu:
- `sudo apt install libavcodec-dev libavutil-dev libswscale-dev`

## CMake options
- `-DP2PCHAT_ENABLE_VIDEO=ON` (default): enables Linux V4L2 + FFmpeg webcam support.
- `-DP2PCHAT_ENABLE_VOICE=ON` is also required because call/session control currently piggybacks on the voice call path.

## Capabilities dump
Build and run:
- `cmake --build build -j --target v4l2_dump_modes`
- `./build/v4l2_dump_modes`

This prints device -> format -> size -> fps using direct V4L2 ioctls, not `v4l2-ctl`.

## Manual test checklist
1. Open Settings -> Video.
2. Pick device / format / resolution / fps / codec / bitrate.
3. Start Preview and verify local camera image updates.
4. Start a call between two clients, verify remote video appears.
5. Stop/start camera sharing and verify state changes are reflected remotely.
6. Unplug camera while sharing and verify app stays stable.
7. Simulate packet loss and ensure:
   - incomplete frames drop without crash
   - keyframe request recovers stream.

## Notes
- Transport uses app UDP P2P path with custom `VPKT` fragmentation header.
- Reassembly + jitter buffering are best-effort and tuned for low latency.
- Unsupported codec/device combinations fall back to nearest supported mode where possible.
- Remote keyframe recovery uses a control message: `video_keyframe_request`.
