package netty.debug;

import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelOption;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.nio.NioDatagramChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.codec.dns.DatagramDnsQuery;
import io.netty.handler.codec.dns.DatagramDnsQueryDecoder;
import io.netty.handler.codec.dns.DatagramDnsResponse;
import io.netty.handler.codec.dns.DatagramDnsResponseEncoder;
import io.netty.handler.codec.dns.DefaultDnsRawRecord;
import io.netty.handler.codec.dns.DnsQuestion;
import io.netty.handler.codec.dns.DnsRecordType;
import io.netty.handler.codec.dns.DnsResponse;
import io.netty.handler.codec.dns.DnsResponseCode;
import io.netty.handler.codec.dns.DnsSection;
import io.netty.resolver.ResolvedAddressTypes;
import io.netty.resolver.SimpleNameResolver;
import io.netty.resolver.dns.DnsNameResolver;
import io.netty.resolver.dns.DnsNameResolverBuilder;
import io.netty.resolver.dns.NoopAuthoritativeDnsServerCache;
import io.netty.resolver.dns.NoopDnsCache;
import io.netty.resolver.dns.NoopDnsCnameCache;
import io.netty.resolver.dns.SingletonDnsServerAddressStreamProvider;
import io.netty.util.concurrent.DefaultThreadFactory;
import io.netty.util.concurrent.FutureListener;

import java.io.IOException;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.UnknownHostException;
import java.util.List;
import java.util.concurrent.TimeUnit;

public final class Main {

  public static void main(final String... args) throws IOException, InterruptedException {
    final int port = setupDnsServer();
    final SimpleNameResolver resolver = resolver(port);
    resolver
        .resolveAll("test.example.com.")
        .addListener(
                (FutureListener<List<InetAddress>>) future -> {
                    if (future.isSuccess()) {
                        System.out.println(future.getNow().get(0).getHostAddress());
                    }
                });
  }

  private static DnsNameResolver resolver(int port) {
    final EventLoopGroup ioExecutor = new NioEventLoopGroup(1, new DefaultThreadFactory("test"));
    final DnsNameResolverBuilder builder =
        new DnsNameResolverBuilder(ioExecutor.next())
            .channelType(NioDatagramChannel.class)
            .socketChannelType(NioSocketChannel.class)
            .queryTimeoutMillis(5000)
            .optResourceEnabled(false)
            .recursionDesired(true)
            .completeOncePreferredResolved(true);
    builder.authoritativeDnsServerCache(NoopAuthoritativeDnsServerCache.INSTANCE);
    builder.resolveCache(NoopDnsCache.INSTANCE);
    builder.cnameCache(NoopDnsCnameCache.INSTANCE);
    builder.resolvedAddressTypes(ResolvedAddressTypes.IPV6_PREFERRED);
    builder.nameServerProvider(
        new SingletonDnsServerAddressStreamProvider(new InetSocketAddress("127.0.0.1", port)));
    return builder.build();
  }

  private static int setupDnsServer() throws IOException, InterruptedException {
    NioEventLoopGroup group = new NioEventLoopGroup();
    Bootstrap bootstrap =
        new Bootstrap()
            .group(group)
            .channel(NioDatagramChannel.class)
            .handler(
                new ChannelInitializer<Channel>() {
                  @Override
                  protected void initChannel(Channel ch) throws Exception {
                    ch.pipeline().addLast(new DatagramDnsQueryDecoder());
                    ch.pipeline().addLast(new DatagramDnsResponseEncoder());
                    ch.pipeline()
                        .addLast(
                            new SimpleChannelInboundHandler<DatagramDnsQuery>() {
                              @Override
                              protected void channelRead0(
                                  ChannelHandlerContext ctx, DatagramDnsQuery query)
                                  throws Exception {
                                final DnsQuestion question = query.recordAt(DnsSection.QUESTION);
                                final DatagramDnsResponse response =
                                    new DatagramDnsResponse(
                                            query.recipient(), query.sender(), query.id())
                                        .addRecord(DnsSection.QUESTION, question);
                                DnsResponseHandler.handle(ctx, response);
                              }
                            });
                  }
                })
            .option(ChannelOption.SO_BROADCAST, true);
    final int port = findUnusedLocalPort();
    bootstrap.bind("127.0.0.1", port).sync();
    return port;
  }

  /** TODO: This is known to be racy, if it turns out to be a source of test flakes, please fix. */
  private static int findUnusedLocalPort() throws IOException, InterruptedException {
      ServerSocket serverSocket = new ServerSocket(0);
      while (!serverSocket.isBound()) {
          Thread.sleep(50);
      }
      return serverSocket.getLocalPort();
  }

  static class DnsResponseHandler {
    static void handle(final ChannelHandlerContext ctx, final DnsResponse response) {
      final DnsQuestion question = response.recordAt(DnsSection.QUESTION);
      final DnsRecordType recordType = question.type();
      if (DnsRecordType.A.equals(recordType)) {
        DnsResponseHandler.aRecords(ctx, response);
      } else if (DnsRecordType.AAAA.equals(recordType)) {
        DnsResponseHandler.aaaaRecords(ctx, response);
      } else {
        DnsResponseHandler.nxDomain(ctx, response);
      }
    }

    private static void aRecords(final ChannelHandlerContext ctx, final DnsResponse response) {
      final DnsQuestion question = response.recordAt(DnsSection.QUESTION);

      ctx.executor()
          .schedule(
                  () -> {
                      try {
                          response.addRecord(
                                  DnsSection.ANSWER,
                                  new DefaultDnsRawRecord(
                                          question.name(),
                                          DnsRecordType.A,
                                          60,
                                          Unpooled.wrappedBuffer(InetAddress.getByName("127.0.0.1").getAddress())));
                          ctx.writeAndFlush(response);
                      } catch (UnknownHostException e) {
                          DnsResponseHandler.nxDomain(ctx, response);
                      }
                  },
              0,
              TimeUnit.SECONDS);
    }

    private static void aaaaRecords(final ChannelHandlerContext ctx, final DnsResponse response) {
      final DnsQuestion question = response.recordAt(DnsSection.QUESTION);
      ctx.executor()
          .schedule(
                  () -> {
                      try {
                          response.addRecord(
                                  DnsSection.ANSWER,
                                  new DefaultDnsRawRecord(
                                          question.name(),
                                          DnsRecordType.AAAA,
                                          60,
                                          Unpooled.wrappedBuffer(Inet6Address.getByName("::1").getAddress())));
                          ctx.writeAndFlush(response);
                      } catch (UnknownHostException e) {
                          DnsResponseHandler.nxDomain(ctx, response);
                      }
                  },
              3,
              TimeUnit.SECONDS);
    }

    private static void nxDomain(final ChannelHandlerContext ctx, final DnsResponse response) {
      response.setCode(DnsResponseCode.NXDOMAIN);
      ctx.writeAndFlush(response);
    }
  }
}
