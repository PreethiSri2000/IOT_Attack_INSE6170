from kivy.app import App
from kivy.uix.screenmanager import ScreenManager, Screen
from kivy.uix.floatlayout import FloatLayout
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from kivy.uix.button import Button

class PacketSnifferScreen(Screen):
    def __init__(self, **kwargs):
        super(PacketSnifferScreen, self).__init__(**kwargs)
        self.layout = FloatLayout()

        # Simple label (will be shown later after button click)
        self.packet_input_label = Label(
            text="Enter packet count:",
            size_hint=(0.6, 0.1),
            pos_hint={"center_x": 0.5, "top": 0.75},
        )

        # Simple text input (will be shown later after button click)
        self.packet_input = TextInput(
            hint_text="Packet Count",
            size_hint=(0.4, 0.08),
            pos_hint={"center_x": 0.5, "top": 0.65},
        )

        # Button to trigger showing the packet input field
        self.show_input_button = Button(
            text="Show Packet Input",
            size_hint=(0.3, 0.1),
            pos_hint={"center_x": 0.5, "top": 0.85},
        )
        self.show_input_button.bind(on_press=self.show_packet_input)

        # Add button to layout
        self.layout.add_widget(self.show_input_button)

        # Add layout to screen
        self.add_widget(self.layout)

    def show_packet_input(self, instance):
        """Dynamically show the packet input field and label."""
        # Add the label and input field to layout only when button is clicked
        self.layout.add_widget(self.packet_input_label)
        self.layout.add_widget(self.packet_input)

        # Disable button after it's clicked
        self.show_input_button.disabled = True


class MyApp(App):
    def build(self):
        sm = ScreenManager()

        packet_sniffer_screen = PacketSnifferScreen(name="packet_sniffer")
        sm.add_widget(packet_sniffer_screen)
        sm.current = "packet_sniffer"

        return sm

if __name__ == '__main__':
    MyApp().run()
