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
    /// Buffer size (in bytes).
    bufsize: u64,
    /// Injection rate (in micro-seconds).
    messages: u64,
}

/// Associate functions for Program Arguments
impl ProgramArguments {
    // Default buffer size.
    const DEFAULT_BUFSIZE: u64 = 1024;
    /// Default local address.
    const DEFAULT_LOCAL: &'static str = "127.0.0.1:12345";
    // Default injection rate.
    const DEFAULT_MESSAGES: u64 = 1000;

    /// Parses the program arguments from the command line interface.
    pub fn new(app_name: &'static str, app_author: &'static str, app_about: &'static str) -> Result<Self> {
        let matches: ArgMatches = Command::new(app_name)
            .author(app_author)
            .about(app_about)
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
            .arg(
                Arg::new("local")
                    .long("local")
                    .value_parser(clap::value_parser!(String))
                    .required(true)
                    .value_name("ADDRESS:PORT")
                    .help("Sets local address"),
            )
            .get_matches();

        // Default arguments.
        let mut args: ProgramArguments = ProgramArguments {
            local: SocketAddrV4::from_str(Self::DEFAULT_LOCAL)?,
            bufsize: Self::DEFAULT_BUFSIZE,
            messages: Self::DEFAULT_MESSAGES,
        };

        // Local address.
        if let Some(addr) = matches.get_one::<String>("local") {
            args.set_local_addr(addr)?;
        }
        // Buffer size.
        if let Some(bufsize) = matches.get_one::<String>("bufsize") {
            args.set_bufsize(bufsize)?;
        }
        // Number of messages.
        if let Some(messages) = matches.get_one::<String>("messages") {
            println!("Message size passed: {}", messages);
            args.set_messages(messages)?;
        }

        Ok(args)
    }

    /// Returns the local endpoint address parameter stored in the target program arguments.
    pub fn get_local(&self) -> SocketAddrV4 {
        self.local
    }

    /// Sets the local address and port number parameters in the target program arguments.
    fn set_local_addr(&mut self, addr: &str) -> Result<()> {
        self.local = SocketAddrV4::from_str(addr)?;
        Ok(())
    }

    /// Returns the buffer size parameter stored in the target program arguments.
    pub fn get_bufsize(&self) -> u64 {
        self.bufsize
    }

    /// Returns the injection rate parameter stored in the target program arguments.
    pub fn get_messages(&self) -> u64 {
        self.messages
    }

    /// Sets the buffer size parameter in the target program arguments.
    fn set_bufsize(&mut self, bufsize_str: &str) -> Result<()> {
        let bufsize: u64 = bufsize_str.parse()?;
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
            bail!("invalid number of messages")
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
    /// Buffer size.
    bufsize: u64,
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
        let bufsize: u64 = args.get_bufsize();
        let messages: u64 = args.get_messages();

        // Create UDP socket.
        let sockqd: QDesc = match libos.socket(libc::AF_INET, libc::SOCK_DGRAM, 0) {
            Ok(qd) => qd,
            Err(e) => panic!("failed to create socket: {:?}", e.cause),
        };

        // Bind to local address.
        match libos.bind(sockqd, local) {
            Ok(()) => (),
            Err(e) => panic!("failed to bind socket: {:?}", e.cause),
        };

        println!("Local Address: {:?}", local);
        println!("Expected messages: {}", messages);
        println!("Message size: {}", bufsize);

        Self {
            libos,
            sockqd,
            bufsize,
            messages,
        }
    }

    /// Runs the target echo server.
    pub fn run(&mut self) {
        let mut start_time = Instant::now();
        let mut count: u64 = 0;
        while count < self.messages {
            // Push the receive request
            let qt: QToken = match self.libos.pop(self.sockqd) {
                Ok(qt) => qt,
                Err(e) => panic!("failed to pop: {:?}", e.cause),
            };

            // Wait to receive
            match self.libos.wait2(qt) {
                Ok(_) => {
                    if count == 0 {
                        start_time = Instant::now();
                    }
                    count += 1;
                },
                Err(e) => panic!("operation failed: {:?}", e.cause),
            };
        }
        let elapsed_time_ns = start_time.elapsed().as_nanos();

        // Compute and print results
        let mbps = ((count * self.bufsize * 8) as f64 * 1000.0) / elapsed_time_ns as f64;
        let throughput = (count as f64 * 1000.0) / elapsed_time_ns as f64;
        println!(
            "{},{},{:.3},{:.3},{:.3}",
            count,
            self.bufsize,
            elapsed_time_ns as f64 / 1000.0,
            throughput,
            mbps
        );
    }
}

//==============================================================================

fn main() -> Result<()> {
    let args: ProgramArguments = ProgramArguments::new(
        "udp-echo",
        "Pedro Henrique Penna <ppenna@microsoft.com>",
        "Echoes UDP packets.",
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
