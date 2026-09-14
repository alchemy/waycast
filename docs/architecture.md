# Architecture

## Overview

This project implements a Miracast source for wlroots-based compositors.

## Components

### doctor
Environment validation and system capability checks.

### capture
wlroots-based compositor screencast capture via xdg-desktop-portal-wlr and PipeWire.

### stream
Video/audio encoding and GStreamer pipeline management.

### net
Sink discovery, P2P group formation, Wi-Fi Direct via NetworkManager.

### networkd
Privileged system D-Bus helper that owns P2P activation and temporary UFW
allowances. The daemon requests sessions through this helper; capture, encoding
and RTSP run in the unprivileged application. See
[automatic networking](network-helper.md) for installation and cleanup behavior.

### rtsp
Miracast/WFD RTSP negotiation protocol implementation.

### daemon
Session orchestration and lifecycle management.

### cli
Command-line interface for operators.

## Dependencies

- wlroots-based compositor (Sway, River, Labwc, Hyprland, etc.)
- xdg-desktop-portal-wlr
- PipeWire
- GStreamer
- NetworkManager / wpa_supplicant
- UFW / Polkit / waycast-networkd for managed session networking
