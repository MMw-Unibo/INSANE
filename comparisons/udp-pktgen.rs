// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#![cfg_attr(feature = "strict", deny(warnings))]
#![deny(clippy::all)]

//==============================================================================
// Imports
//==============================================================================

use ::anyhow::{
    bail,
    Result,
};
use ::clap::{
    Arg,
    ArgMatches,
    Command,
};
use ::demikernel::{
    LibOS,
    LibOSName,
    OperationResult,
    QDesc,
    QToken,
};
use ::std::{
    net::SocketAddrV4,
    str::FromStr,
    time::{
        Duration,
        Instant,
    },
};

//==============================================================================
// Program Arguments
//==============================================================================

/// Program Arguments
#[derive(Debug)]
pub struct ProgramArguments {
    /// Local socket IPv4 address.
    local: SocketAddrV4,
    /// Remote socket IPv4 address.
    remote: SocketAddrV4,
    /// Buffer size (in bytes).
    bufsize: usize,
    /// Injection rate (in micro-seconds).
    messages: u64,
}

/// Associate functions for Program Arguments
impl ProgramArguments {
    // Default buffer size.
    const DEFAULT_BUFSIZE: usize = 1024;
    /// Default local address.
    const DEFAULT_LOCAL: &'static str = "127.0.0.1:12345";
    // Default number of messages.
    const DEFAULT_MESSAGES: u64 = 100;
    /// Default host address.
    const DEFAULT_REMOTE: &'static str = "127.0.0.1:23456";

    /// Parses the program arguments from the command line interface.
    pub fn new(app_name: &'static str, app_author: &'static str, app_about: &'static str) -> Result<Self> {
        let matches: ArgMatches = Command::new(app_name)
            .author(app_author)
            .about(app_about)
            .arg(
                Arg::new("local")
                    .long("local")
                    .value_parser(clap::value_parser!(String))
                    .required(false)
                    .value_name("ADDRESS:PORT")
                    .help("Sets local address"),
            )
            .arg(
                Arg::new("remote")
                    .long("remote")
                    .value_parser(clap::value_parser!(String))
                    .required(true)
                    .value_name("ADDRESS:PORT")
                    .help("Sets remote address"),
            )
            .arg(
                Arg::new("bufsize")
                    .long("bufsize")
                    .value_parser(clap::value_parser!(String))
                    .required(true)
                    .value_name("SIZE")
                    .help("Sets buffer size"),
            )
            .arg(
                Arg::new("messages")
                    .long("messages")
                    .value_parser(clap::value_parser!(String))
                    .required(true)
                    .value_name("MSGS")
                    .help("Sets packet injection rate"),
            )
            .get_matches();

        // Default arguments.
        let mut args: ProgramArguments = ProgramArguments {
            local: SocketAddrV4::from_str(Self::DEFAULT_LOCAL)?,
            remote: SocketAddrV4::from_str(Self::DEFAULT_REMOTE)?,
            bufsize: Self::DEFAULT_BUFSIZE,
            messages: Self::DEFAULT_MESSAGES,
        };

        // Local address.
        if let Some(addr) = matches.get_one::<String>("local") {
            args.set_local_addr(addr)?;
        }

        // Remote address.
        if let Some(addr) = matches.get_one::<String>("remote") {
            args.set_remote_addr(addr)?;
        }

        // Buffer size.
        if let Some(bufsize) = matches.get_one::<String>("bufsize") {
            args.set_bufsize(bufsize)?;
        }

        // Number of messages.
        if let Some(messages) = matches.get_one::<String>("messages") {
            args.set_messages(messages)?;
        }

        Ok(args)
    }

    /// Returns the local endpoint address parameter stored in the target program arguments.
    pub fn get_local(&self) -> SocketAddrV4 {
        self.local
    }

    /// Returns the remote endpoint address parameter stored in the target program arguments.
    pub fn get_remote(&self) -> SocketAddrV4 {
        self.remote
    }

    /// Returns the buffer size parameter stored in the target program arguments.
    pub fn get_bufsize(&self) -> usize {
        self.bufsize
    }

    /// Returns the injection rate parameter stored in the target program arguments.
    pub fn get_messages(&self) -> u64 {
        self.messages
    }

    /// Sets the local address and port number parameters in the target program arguments.
    fn set_local_addr(&mut self, addr: &str) -> Result<()> {
        self.local = SocketAddrV4::from_str(addr)?;
        Ok(())
    }

    /// Sets the remote address and port number parameters in the target program arguments.
    fn set_remote_addr(&mut self, addr: &str) -> Result<()> {
        self.remote = SocketAddrV4::from_str(addr)?;
        Ok(())
    }

    /// Sets the buffer size parameter in the target program arguments.
    fn set_bufsize(&mut self, bufsize_str: &str) -> Result<()> {
        let bufsize: usize = bufsize_str.parse()?;
        if bufsize > 0 {
            self.bufsize = bufsize;
            Ok(())
        } else {
            bail!("invalid buffer size")
        }
    }

    /// Sets the injection rate parameter in the target program arguments.
    fn set_messages(&mut self, messages_str: &str) -> Result<()> {
        let messages: u64 = messages_str.parse()?;
        if messages > 0 {
            self.messages = messages;
            Ok(())
        } else {
            bail!("invalid injection rate")
        }
    }
}

//==============================================================================
// Application
//==============================================================================

/// Application
struct Application {
    /// Underlying libOS.
    libos: LibOS,
    // Local socket descriptor.
    sockqd: QDesc,
    /// Remote endpoint.
    remote: SocketAddrV4,
    /// Buffer size.
    bufsize: usize,
    /// Injection rate
    messages: u64,
}

/// Associated Functions for the Application
impl Application {
    /// Logging interval (in seconds).
    const LOG_INTERVAL: u64 = 5;

    /// Instantiates the application.
    pub fn new(mut libos: LibOS, args: &ProgramArguments) -> Self {
        // Extract arguments.
        let local: SocketAddrV4 = args.get_local();
        let remote: SocketAddrV4 = args.get_remote();
        let bufsize: usize = args.get_bufsize();
        let messages: u64 = args.get_messages();

        // Create UDP socket.
        let sockqd: QDesc = match libos.socket(libc::AF_INET, libc::SOCK_DGRAM, 1) {
            Ok(qd) => qd,
            Err(e) => panic!("failed to create socket: {:?}", e.cause),
        };

        // Bind to local address.
        match libos.bind(sockqd, local) {
            Ok(()) => (),
            Err(e) => panic!("failed to bind socket: {:?}", e.cause),
        };

        println!("Local Address:  {:?}", local);
        println!("Remote Address: {:?}", remote);
        println!("Expected messages: {}", messages);
        println!("Message size: {}", bufsize);

        Self {
            libos,
            sockqd,
            remote,
            bufsize,
            messages,
        }
    }

    /// Runs the target application.
    pub fn run(&mut self) {
        let start: Instant = Instant::now();
        let mut nbytes: usize = 0;
        let mut num_pkt: u64 = 0;
        let mut last_push: Instant = Instant::now();
        let mut last_log: Instant = Instant::now();
        let data: Vec<u8> = Self::mkbuf(self.bufsize, 0x65);

        while num_pkt < self.messages {
            // // Dump statistics.
            // if last_log.elapsed() > Duration::from_secs(Self::LOG_INTERVAL) {
            //     let elapsed: Duration = Instant::now() - start;
            //     println!("{:?} B / {:?} us", nbytes, elapsed.as_micros());
            //     last_log = Instant::now();
            // }

            // Push packet.
            // if last_push.elapsed() > Duration::from_nanos(self.messages) {
            let qt: QToken = match self.libos.pushto2(self.sockqd, &data, self.remote) {
                Ok(qt) => qt,
                Err(e) => panic!("failed to push data to socket: {:?}", e.cause),
            };
            match self.libos.wait2(qt) {
                Ok((_, OperationResult::Push)) => (),
                Err(e) => panic!("operation failed: {:?}", e.cause),
                _ => panic!("unexpected result"),
            };
            num_pkt += 1;
            // nbytes += self.bufsize;
            // last_push = Instant::now();
            // }
        }
    }

    /// Makes a buffer.
    fn mkbuf(bufsize: usize, fill_char: u8) -> Vec<u8> {
        let mut data: Vec<u8> = Vec::<u8>::with_capacity(bufsize);

        for _ in 0..bufsize {
            data.push(fill_char);
        }

        data
    }
}

//==============================================================================

/// Drives the application.
fn main() -> Result<()> {
    let args: ProgramArguments = ProgramArguments::new(
        "udp-pktgen",
        "Pedro Henrique Penna <ppenna@microsoft.com>",
        "Generates UDP traffic.",
    )?;

    let libos_name: LibOSName = match LibOSName::from_env() {
        Ok(libos_name) => libos_name.into(),
        Err(e) => panic!("{:?}", e),
    };
    let libos: LibOS = match LibOS::new(libos_name) {
        Ok(libos) => libos,
        Err(e) => panic!("failed to initialize libos: {:?}", e.cause),
    };

    Application::new(libos, &args).run();

    Ok(())
}
