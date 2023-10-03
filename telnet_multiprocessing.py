import telnetlib
import multiprocessing
import traceback
import logging


#### Codigo Python para ajudar analistas e engenheiros de rede a executar vários equipamentos legados (telnet) de forma rápida ###


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class CommandosEmMassa:
    def __init__(self, username, password, devices, commands):
        self.username = username
        self.password = password
        self.devices = devices
        self.commands = commands

    def execute_commands(self, device_ip):
        try:
            with telnetlib.Telnet(device_ip) as tn:
                tn.read_until(b"Username:", timeout=5)
                tn.write(self.username.encode('ascii') + b"\n")
                tn.read_until(b"Password:", timeout=5)
                tn.write(self.password.encode('ascii') + b"\n")

                for command in self.commands:
                    tn.read_until(b"#", timeout=5)  # Aguarde o prompt estar pronto
                    tn.write(command.encode('ascii') + b"\n")

                output = tn.read_until(b"#", timeout=5).decode('ascii')
                logger.info(f"Output from {device_ip} for last command '{self.commands[-1]}':\n")
                logger.info('########\n' + output)

        except Exception as e:
            logger.error(f"Error on {device_ip}: {str(e)}")
            traceback.print_exc()

    def run(self):
        processes = []

        for device_ip in self.devices:
            process = multiprocessing.Process(target=self.execute_commands, args=(device_ip,))
            processes.append(process)
            process.start()

        for process in processes:
            process.join()

if __name__ == "__main__":
    # Defina suas informações de configuração aqui
    username = '' # seu usuario aqui #
    password = '' # sua senha aqui #
    devices = ['10.22.0.1', '10.22.0.114']  # Adicione seus IPs de dispositivo aqui
    commands = ['copy runn', 'exit'] # comandos aqui #

    cmd_massa = CommandosEmMassa(username, password, devices, commands)
    cmd_massa.run()