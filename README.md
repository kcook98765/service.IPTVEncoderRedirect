# service.IPTVEncoderRedirect
Middle ware for kodi IPTV Merge.

1) You will need at least one kodi device capable of utilizing Widevine DRM:
https://www.matthuisman.nz/2018/05/kodi-widevine-support.html
(and can test with the metioned "video test stream addon")
NOTE: These will be dedicated devices (or just 1 if that is all you need), only for use with encoder, do not add a library, etc, it will not be used for normal kodi thigs, just playback via the addons.

2) A vdieo encoder capable of HLS streaming, like:
https://www.amazon.com/dp/B07TKMPCZH

3) IPTV.Merge found at:
https://www.matthuisman.nz/2019/02/iptv-merge-kodi-add-on.html

4) HULU (though you should be able to use any IPTV.merge aware addon, and even multiple addons) :
https://www.matthuisman.nz/2021/10/hulu-kodi-add-on.html


I am testing my Hulu Account.

Once you have setup the kodi device along with IPTV.merge and at least one IPTV.merge "Aware" addon (like HULU), install my addon.

Go to setting for my addon, and set up at least the top 3 entries (pertain to this device, the rest are for additional kodi devices, for example if you have multi port encoder).

Top setting is for the IP of the kodi device.

Next is the port for the main server the addon will run (and used in setup of m3u8 and epg urls for your DVR)

Last is the encoder url for the HLS streaming (be sure to enable HLS at the encoder).

You will need to reboot after applying the settings (for now, will figure out a way to do this from settings for quick reload of addon).

There will be a simple "status" page you can access by:

http://__KODI_IP__:__PORT__/status

(in my case, kodi on 192.168.2.9 port 9191, so http://192.168.2.9:9191/status).

This is a very simple status page showing the proxy(ies) setup and their status (normally IDLE unless actively serving/playing content).

For your DVR (mine is ChannelsDVR) setup source with:

m3u8 url:

http://__KODI_IP__:__PORT__/playlist.m3u8

EPG xml:

http://__KODI_IP__:__PORT__/epg.xml

If you experiment with multiple kodi servers, you may want to limit the # of streams (in my case HULU only allows 2 concurrent streams).

That is it, onnce DVR has gathered the data, you should have access.

When you start a video from the DVR, it connects to the addon, the addon checks if a proxy/kodi box is free, initiates the playback and redirects the connection to the proxy url to begin the streaming.

There is a delay as the kodi box addon (like HULU) actually starts up (you should see the Kodi GUI as it starts up in the stream).

For my Raspberry Pi 3B , this can take 30 seconds or so.

The addon code proxy server is in the middle of the stream, it simply redirects the HLS .ts to the encoder, but for the .m3u8 segments, it opens the m3u8 from the encoder and immediatly sends to the client. This is done so that there is always traffic hitting the addon code so it can monitor for activity, if the code notices it has been longer than apx 15 seconds (whhich for HLS streams, should not happen unless stream is shut down at client, or some other network issue), it will halt any playback by kodi, returning the proxy to a statsu to enable a new stream to be started upon request.

The code also identifies if a new request matches an already running stream, and so should allow multiple streams to the same proxy.

But if all proxies are in use, the addon wil send a 503 (All encoders busy!) response.

My next steps are to try running multiple kodi boxes (you do not need the addon on the additional boxes, as the Master one can interact remoetly with the other boxes to start/stop playback).

More to come...
